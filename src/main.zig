const std = @import("std");
const process = std.process;
const Ast = std.zig.Ast;
const assert = std.debug.assert;
const FileSet = std.AutoHashMap(std.fs.File.INode, void);

const Zoogle = @import("zoogle.zig");

const Color = @import("color.zig").Color;

const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();

const File = std.fs.File;
const Dir = std.fs.Dir;

var fn_time: i64 = 0;
var fn_ct: usize = 0;
var type_time: i64 = 0;
var type_ct: usize = 0;

fn PrintUsage() void {
    std.debug.print("zoogle $path_to_file $search_string [-r $recursive_depth]\n", .{});
    std.debug.print("{s: >8} path_to_file = {{\"std\" | relative_path}}\n", .{"where"});
    std.debug.print("{s: >8} search_string = \"fn [$fn_name]([$var_name]: $var_type, ...) $var_type\"\n", .{"where"});
}







fn PrintExpr(writer: anytype, tree: Ast, type_index: Ast.Node.Index) !void {
    const first_token = tree.firstToken(type_index);
    const last_token = tree.lastToken(type_index);
    for (first_token..last_token + 1) |i| {
        _ = try writer.print("{s}", .{Zoogle.tokenRender(tree, @intCast(i))});
    }
}


fn PrintFn(writer: anytype, tree: Ast, fnProto: Ast.full.FnProto) !void {
    if (fnProto.visib_token) |v| {
        try writer.print("{s} ", .{Zoogle.tokenRender(tree, v)});
    }
    try writer.print("fn {s}(", .{Zoogle.tokenRender(tree, fnProto.name_token)});
    var iterator = fnProto.iterate(&tree);
    while (iterator.next()) |param| {
        try writer.print("{s}: ", .{Zoogle.tokenRender(tree, param.name_token)});
        try PrintExpr(writer, tree, param.type_expr);
        if (iterator.param_i != fnProto.ast.params.len) try writer.print(", ", .{});
    }
    _ = try writer.write(") ");
    if (fnProto.ast.callconv_expr != 0) {
        _ = try writer.write("callconv(");
        try PrintExpr(writer, tree, fnProto.ast.callconv_expr);
        _ = try writer.write(") ");
    }
    try PrintExpr(writer, tree, fnProto.ast.return_type);
    _ = try writer.write("\n");
}

var recursive_depth: u32 = 1;

pub fn main() !void {
    errdefer PrintUsage();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);
    if (args.len <= 1) {
        return error.ExpectFileArgument;
    }
    if (args.len <= 2) {
        return error.ExpectMatchArgument;
    }

    if (args.len >= 4) {
        if (!std.mem.eql(u8, args[3], "-r")) return error.InvalidArgumentOption;
        if (args.len >= 5) {
            recursive_depth = std.fmt.parseInt(u32, args[4], 10) catch |e| {
                std.log.err("Failed to parse options after \"-r\", expect u32, got \"{s}\"", .{args[4]});
                return e;
            };
        }
    }

    const file_name = args[1];
    const match_string = args[2];

    var fn_queue = try Zoogle.Search(allocator, match_string, file_name, recursive_depth);
    defer fn_queue.deinit();
    // var buffer: [1]Ast.Node.Index = undefined;
    while (fn_queue.removeOrNull()) |fr| {
        try stdout.print("{s}{s}:{}:{}{s} {s}{s}{s}\n", .{ Color.KYEL, fr.location.file, fr.location.line, fr.location.column, Color.KRST, Color.KCYN, fr.fnString, Color.KRST });
        // const rel_path = RelativePathFromCwd(allocator, fr.)
        allocator.free(fr.fnString);
        allocator.free(fr.location.file);
        allocator.destroy(fr);
    }

    try bw.flush();


}

fn add(a: i32, b: i32) i32 {
    return a + b;
}

fn debugAst(ast: Ast) void {
    const debug = std.log.debug;
    debug("[{}]Nodes", .{ast.nodes.len});
    for (ast.nodes.items(.tag), 0..) |t, i| {
        debug("[{}]: {} = \"{s}\"", .{ i, t, Zoogle.tokenRender(ast, ast.nodes.items(.main_token)[i]) });
    }
    // try stdout.print("token tags:\n", .{});
    debug("[{}]Tokens", .{ast.tokens.len});
    for (ast.tokens.items(.tag), 0..) |t, i| {
        if (t == .invalid) break;
        debug("[{}]: {} = \"{s}\"", .{ i, t, Zoogle.tokenRender(ast, @intCast(i)) });
    }
}
const ta = std.testing.allocator;

test "Split" {
    const stderr = std.io.getStdErr().writer();
    const split_fn_str =
        \\pub fn splitAny(comptime T: type, buffer: []const T, delimiters: []const T) SplitIterator(T, .any) {
        \\  return .{
        \\    .index = 0,
        \\    .buffer = buffer,
        \\    .delimiter = delimiters,
        \\  };
        \\}
    ;
    // std.debug.print("\nTesting: {s}\n", .{split_fn_str});
    var ast = try Ast.parse(ta, split_fn_str, .zig);
    defer ast.deinit(ta);
    var buf: Ast.Node.Index = undefined;
    const fn_proto = try Zoogle.ParseFuncDecl(&ast, &buf);

    const match_fn_str = "fn split(type, []const T, []const T) SplitIterator";
    var match_ast = try Ast.parse(ta, match_fn_str, .zig);
    defer match_ast.deinit(ta);
    var match_buf: Ast.Node.Index = undefined;
    const match_fn_proto = try Zoogle.ParseFuncInline(&match_ast, &match_buf);

    std.debug.print("\n{}\n", .{fn_proto});
    debugAst(ast);
    try PrintFn(stderr, ast, fn_proto);

    std.debug.print("\n{}\n", .{match_fn_proto});
    debugAst(match_ast);
    try PrintFn(stderr, match_ast, match_fn_proto);
    var t1 = std.time.microTimestamp();
    const return_dist1 = Zoogle.FuzzyMatchType(ta, &match_ast, &ast, match_fn_proto.ast.return_type, fn_proto.ast.return_type);
    t1 = std.time.microTimestamp() - t1;
    std.debug.print("FuzzyMatchType(return_type) => {}, {} microseconds\n", .{ return_dist1, t1 });

    // const ta = std.heap.testAllocator(st)
}
