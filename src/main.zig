const std = @import("std");
const process = std.process;
const Ast = std.zig.Ast;
const assert = std.debug.assert;
const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();
fn tokenRender(tree: Ast, token_index: ?Ast.TokenIndex) []const u8 {
    if (token_index) |i| {
        return Ast.tokenSlice(tree, i);
    }
    return "";
}

fn typeFormat(tree: Ast, buf: []u8, node_index: Ast.Node.Index) !void {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    const allocator = fba.allocator();
    const first_token = tree.firstToken(node_index);
    const last_token = tree.lastToken(node_index);
    const allocPrint = std.fmt.allocPrint;
    for (first_token..last_token+1) |i| {
        _ = try allocPrint(allocator, "{s}", .{tokenRender(tree, @intCast(i))});
    }

    
}
const OpenError = std.fs.File.OpenError;
const ParseError = error {
    ExpectFileArgument,
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
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.

    
    const file_name = args[1];
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
    for (decls) |d| {



        var buffer: [1]Ast.Node.Index = undefined;
        var fnProto = ast.fullFnProto(&buffer, d) orelse continue;

        const location = ast.tokenLocation(0, fnProto.ast.fn_token);
        var location_buff: [32]u8 = undefined;
        @memset(&location_buff, ' ');
        _ = try std.fmt.bufPrint(&location_buff, "{s}:{}:{} ", .{file_name, location.line, location.column});
        try stdout.print("{s}", .{location_buff});
        try stdout.print("{s: <4} fn {s: <20}(", .{tokenRender(ast, fnProto.visib_token), tokenRender(ast, fnProto.name_token)});
        var iterator = fnProto.iterate(&ast);
        while (iterator.next()) |param| {
            try stdout.print("{s: <10}: ", .{tokenRender(ast, param.name_token)});
            var param_type_buff: [256]u8 = undefined;
            @memset(&param_type_buff, 0);
            try typeFormat(ast, @ptrCast(&param_type_buff), param.type_expr);
            try stdout.print("{s: <15}", .{param_type_buff});
            if (iterator.param_i != fnProto.ast.params.len) try stdout.print(", ", .{});
        }
        var return_type_buff: [256]u8 = undefined;
        @memset(&return_type_buff, 0);
        try typeFormat(ast, &return_type_buff, fnProto.ast.return_type);
        try stdout.print(") {s}\n", .{return_type_buff});
        
    }

    // _ = token_tags;
    _ = token_starts;
    try bw.flush();
    // debugAst(ast);

}


fn debugAst(ast: Ast) void {
    const debug = std.log.debug;
    for (ast.nodes.items(.tag), 0..) |t, i| {
        debug("[{}]: {} = \"{s}\"\n", .{i,t, tokenRender(ast, ast.nodes.items(.main_token)[i])});
    }
    // try stdout.print("token tags:\n", .{});

    for (ast.tokens.items(.tag), 0..) |t, i| {
        if (t == .invalid) break;
        debug("[{}]: {} = \"{s}\"\n", .{i, t, tokenRender(ast, @intCast(i)) });
        
    }
}
