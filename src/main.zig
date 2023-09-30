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



fn StdLibrary(lib: []const u8) ![]const u8 {
    if (std.mem.eql(u8, lib, "std")) {
        return "lib/std/std.zig";
    } else if (std.mem.eql(u8, lib, "builtin")) {
        return "lib/std/builtin.zig";
    }
    return error.PacakageNotFound;
}

fn FindFromSysPath(allocator: std.mem.Allocator, file_name: []const u8) ![]const u8 {
    const env_paths = std.os.getenv("PATH") orelse return error.PacakageNotFound;
    var iterator = std.mem.splitScalar(u8, env_paths, ':');
    while (iterator.next()) |env_path| {
        std.log.debug("finding in {s}/{s}", .{ env_path, file_name });
        var temp_dir = std.fs.openDirAbsolute(env_path, .{}) catch continue;
        defer temp_dir.close();
        const package = temp_dir.openFile(file_name, .{ .mode = .read_only }) catch continue;
        defer package.close();
        return try temp_dir.realpathAlloc(allocator, file_name);
    }
    return error.PacakageNotFound;
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

    var match_ast = try Ast.parse(allocator, match_string, .zig);
    defer match_ast.deinit(allocator);
    // debugAst(match_ast);
    var match_fn_node: [1]Ast.Node.Index = undefined;
    const match_fn = eval_fn: {
        break :eval_fn for (match_ast.nodes.items(.tag), 0..) |t, i| {
            _ = t;
            match_fn_node[0] = @intCast(i);
            break match_ast.fullFnProto(&match_fn_node, @intCast(i)) orelse continue;
        } else return error.InvalidMatchSyntax;
    };
    if (match_fn.name_token) |nt| {
        Zoogle.dist_limit += @intCast(Zoogle.tokenRender(match_ast, nt).len);
    }
    var match_param_it = match_fn.iterate(&match_ast);
    while (match_param_it.next()) |p| {
        if (p.name_token) |nt| {
            Zoogle.dist_limit += @intCast(Zoogle.tokenRender(match_ast, nt).len);
        }
    }
    // try stdout.print("input: {s}\n", .{match_string});
    std.log.debug("fn node: {}", .{match_fn_node[0]});
    try PrintFn(stdout, match_ast, match_fn);
    var path_buffer = [_]u8{0} ** 1024;
    var path_fba = std.heap.FixedBufferAllocator.init(&path_buffer);

    var file_set = FileSet.init(allocator);
    defer file_set.deinit();
    var file = try find_file: {
        if (!std.mem.endsWith(u8, file_name, ".zig")) {
            const package_abs_path = try FindFromSysPath(path_fba.allocator(), try StdLibrary(file_name));
            break :find_file std.fs.openFileAbsolute(package_abs_path, .{ .mode = .read_only });
        }
        _ = try std.fs.cwd().realpathAlloc(path_fba.allocator(), file_name);
        break :find_file try std.fs.cwd().openFile(file_name, .{ .mode = .read_only });
    };
    try stdout.print("current path: {s}\n", .{path_buffer});
    try bw.flush();

    try file_set.put(((try file.stat()).inode), {});
    var fn_queue = Zoogle.FnQueue.init(allocator, null);
    defer fn_queue.deinit();
    try stdout.print("recursive depth: {}\n", .{recursive_depth});
    var t = std.time.microTimestamp();
    const ct = try Zoogle.SearchFile(allocator, file, &fn_queue, &match_ast, match_fn, &path_fba, &file_set, recursive_depth);
    t = std.time.microTimestamp() - t;
    try stdout.print("opening {s}\n", .{file_name});
    defer file.close();

    // var buffer: [1]Ast.Node.Index = undefined;
    const found_ct = fn_queue.count();
    while (fn_queue.removeOrNull()) |fr| {
        try stdout.print("{s}{s}:{}:{}{s} {s}{s}{s}\n", .{ Color.KYEL, fr.location.file, fr.location.line, fr.location.column, Color.KRST, Color.KCYN, fr.fnString, Color.KRST });
        // const rel_path = RelativePathFromCwd(allocator, fr.)
        allocator.free(fr.fnString);
        allocator.free(fr.location.file);
        allocator.destroy(fr);
    }
    const average: f64 = @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(ct));
    try stdout.print("stats:\nSearched through {} functions, found {}\nTotal time: {d:.3} ms\nAverage time: {d:.6} ms\n", .{ct, found_ct, @divFloor(t, 1000), @divExact(average, 1000)});

    // _ = token_tags;
    try bw.flush();

    // debugAst(match_ast);

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
