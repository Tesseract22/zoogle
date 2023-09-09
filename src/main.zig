const std = @import("std");
const process = std.process;
const Ast = std.zig.Ast;
const assert = std.debug.assert;

const LevenshteinDistance = @import("distance.zig").LevenshteinDistance;

const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();
fn tokenRender(tree: Ast, token_index: ?Ast.TokenIndex) []const u8 {
    if (token_index) |i| {
        return Ast.tokenSlice(tree, i);
    }
    return "";
}

fn PrintExpr(tree: Ast, type_index: Ast.Node.Index) !void {
    const first_token = tree.firstToken(type_index);
    const last_token = tree.lastToken(type_index);
    for (first_token..last_token+1) |i| {
        _ = try stdout.print("{s}", .{tokenRender(tree, @intCast(i))});
    }
}
fn PrintFn(tree: Ast, fnProto: Ast.full.FnProto) !void {

    if (fnProto.visib_token) |v| {
        try stdout.print("{s} ", .{tokenRender(tree, v)});
    }
    try stdout.print("fn {s}(", .{tokenRender(tree, fnProto.name_token)});
    var iterator = fnProto.iterate(&tree);
    while (iterator.next()) |param| {
        try stdout.print("{s}: ", .{tokenRender(tree, param.name_token)});
        try PrintExpr(tree, param.type_expr);
        if (iterator.param_i != fnProto.ast.params.len) try stdout.print(", ", .{});
    }
    _ = try stdout.write(") ");
    if (fnProto.ast.callconv_expr != 0)  {
        _ = try stdout.write("callconv(");
        try PrintExpr(tree, fnProto.ast.callconv_expr);
        _ = try stdout.write(") ");
    }
    try PrintExpr(tree, fnProto.ast.return_type);
    _ = try stdout.write("\n");
}

fn ExactMatchType(a_tree: *Ast, b_tree: *Ast, a: Ast.Node.Index, b: Ast.Node.Index) bool {
    const a_first = a_tree.firstToken(a);
    const a_last = a_tree.lastToken(a);
    const b_first = b_tree.firstToken(b);
    const b_last = b_tree.lastToken(b);
    if (a_last - a_first != b_last - b_first) return false;
    for (a_first..a_last + 1, b_first..b_last + 1) |ai, bi| {
        const a_tag = a_tree.tokens.items(.tag)[ai];
        const b_tag = b_tree.tokens.items(.tag)[bi];
        if (a_tag != b_tag) return false;
        switch (a_tag) {
            .identifier => {
                if (!std.mem.eql(u8, tokenRender(a_tree.*, @intCast(ai)) , tokenRender(b_tree.*, @intCast(bi)))) return false;
            },
            else => {},
        }
    }
    return true;
}

fn ExactMatchfn(a_tree: *Ast, b_tree: *Ast, a: Ast.full.FnProto, b: Ast.full.FnProto) bool {
    if (!ExactMatchType(a_tree, b_tree, a.ast.return_type, b.ast.return_type)) return false;
    var ai = a.iterate(a_tree);
    var bi = b.iterate(b_tree);
    while (true) {
        const ap = ai.next();
        const bp = bi.next();
        if (ap == null and bp == null) {
            break;
        } else if (ap == null or bp == null) {
            return false;
        }
        if (!ExactMatchType(a_tree, b_tree, ap.?.type_expr, bp.?.type_expr)) {
            return false;
        }
    }
    return true;
}

fn FuzzyMatchIdentifier(allocator: std.mem.Allocator, a_tree: *Ast, b_tree: *Ast, a: Ast.Node.Index, b: Ast.Node.Index) u32 {
    assert(a_tree.nodes.items(.tag)[a] == .identifier);
    assert(b_tree.nodes.items(.tag)[b] == .identifier);
    const a_token = a_tree.nodes.items(.main_token)[a];
    const b_token = a_tree.nodes.items(.main_token)[b];
    return LevenshteinDistance(allocator, tokenRender(a_tree, a_token), tokenRender(b_tree, b_token)) catch std.math.maxInt(u32);
    
}

fn FuzzyMatchType(
                allocator: std.mem.Allocator, 
                a_source: []const u8, b_source: []const u8, 
                a_tree: *Ast, b_tree: *Ast, 
                a: Ast.Node.Index, b: Ast.Node.Index) 
                u32 {
    const a_type = a_source[a_tree.tokens.items(.start)[a_tree.firstToken(a)]..a_tree.tokens.items(.start)[a_tree.lastToken(a)]];
    const b_type = b_source[b_tree.tokens.items(.start)[b_tree.firstToken(b)]..b_tree.tokens.items(.start)[b_tree.lastToken(b)]];
    return 
        (LevenshteinDistance(allocator, a_type, b_type) 
                                                        catch std.math.maxInt(u32)) + 
        (LevenshteinDistance(allocator, tokenRender(a_tree.*, a_tree.lastToken(a)), tokenRender(b_tree.*, b_tree.lastToken(b))) 
                                                        catch std.math.maxInt(u32));
}

fn FuzzyMatchFn(
                allocator: std.mem.Allocator, 
                a_source: []const u8, b_source: []const u8, 
                a_tree: *Ast, b_tree: *Ast, 
                a: Ast.full.FnProto, b: Ast.full.FnProto) 
                u32 {
    var dist: u32 = 0;
    dist += FuzzyMatchType(allocator, a_source, b_source, a_tree, b_tree, a.ast.return_type, b.ast.return_type);
    var ai = a.iterate(a_tree);
    var bi = b.iterate(b_tree);
    while (true) {
        const ap = ai.next();
        const bp = bi.next();
        if (ap == null and bp == null) {
            break;
        } else if (ap == null or bp == null) {
            return std.math.maxInt(u32);
        }
        dist += FuzzyMatchType(allocator, a_source, b_source, a_tree, b_tree, ap.?.type_expr, bp.?.type_expr);
    }
    return dist;
}

const OpenError = std.fs.File.OpenError;
const ParseError = error {
    ExpectFileArgument,
    ExpectMatchArgument,
    InvalidMatchSyntax,
};


pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
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
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.

    
    const file_name = args[1];
    const match_string = args[2];
    var match_ast = try Ast.parse(allocator, match_string, .zig);
    defer match_ast.deinit(allocator);
    // debugAst(match_ast);
    const match_fn = eval_fn: {
        var buffer: [1]Ast.Node.Index = undefined;
        
        break :eval_fn for (match_ast.nodes.items(.tag), 0..) |t, i| {
            _ = t;
            break match_ast.fullFnProto(&buffer, @intCast(i)) orelse continue;
        } else return error.InvalidMatchSyntax;
    };
    try stdout.print("input: {s}\n", .{match_string});
    try PrintFn(match_ast, match_fn);

    var file = std.fs.cwd().openFile(file_name, .{.mode = .read_only}) catch |e| {
        std.log.err("Cannot open file: {s}", .{file_name});
        return e;
    };
    try stdout.print("opening {s}\n", .{file_name});
    defer file.close();

    const file_size = (file.stat() catch |e| {
        std.log.err("Cannot get file size", .{});
        return e;
    }).size;
    const source = allocator.allocSentinel(u8, file_size, 0) catch |e| {
        std.log.err("failed to allocate {} bytes to read file\n", .{file_size});
        return e;
    };
    defer allocator.free(source);
    _ = try file.readAll(source);
    try bw.flush();


    var ast = try Ast.parse(allocator, source, .zig);
    defer ast.deinit(allocator);
    const token_starts = ast.tokens.items(.start);
    const decls = ast.rootDecls();
    _ = try stdout.write("matches:\n");
    const dist_limit = 30;
    for (decls) |d| {


        
        var buffer: [1]Ast.Node.Index = undefined;
        var fnProto = ast.fullFnProto(&buffer, d) orelse continue;
        // if (!ExactMatchfn(&ast,& match_ast, fnProto, match_fn)) continue;
        const distance = FuzzyMatchFn(allocator, source, match_string, &ast, &match_ast, fnProto, match_fn);
        if (distance > dist_limit) continue;

        const location = ast.tokenLocation(0, fnProto.ast.fn_token);
        var location_buff: [128]u8 = undefined;
        @memset(&location_buff, 0);
        _ = try std.fmt.bufPrint(&location_buff, "{s}:{}:{} ", .{file_name, location.line, location.column});
        try stdout.print("{s}", .{location_buff});
        try PrintFn(ast, fnProto);
        
    }
    
    // _ = token_tags;
    _ = token_starts;
    try bw.flush();
    // debugAst(ast);
    // debugAst(match_ast);

}




fn debugAst(ast: Ast) void {
    const debug = std.log.debug;
    debug("[{}]Nodes", .{ast.nodes.len});
    for (ast.nodes.items(.tag), 0..) |t, i| {
        debug("[{}]: {} = \"{s}\"", .{i,t, tokenRender(ast, ast.nodes.items(.main_token)[i])});
    }
    // try stdout.print("token tags:\n", .{});
    debug("[{}]Tokens", .{ast.tokens.len});
    for (ast.tokens.items(.tag), 0..) |t, i| {
        if (t == .invalid) break;
        debug("[{}]: {} = \"{s}\"", .{i, t, tokenRender(ast, @intCast(i)) });
        
    }
}
