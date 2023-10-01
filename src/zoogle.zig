const std = @import("std");
const process = std.process;
const Ast = std.zig.Ast;
const assert = std.debug.assert;
const FileSet = std.AutoHashMap(std.fs.File.INode, void);
const File = std.fs.File;
const Dir = std.fs.Dir;
const LVDistance = @import("distance.zig");
const LevenshteinDistance = LVDistance.LevenshteinDistance;
const LevenshteinDistanceOptions = LVDistance.LevenshteinDistanceOptions;


fn RelativePathFromCwd(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    // path: "/abc/123/"
    // cwd:  "/abc/1234/xyz/"
    // ../../123

    // path: "/abc/1234/xyz/"
    // cwd:  "/abc/123/"
    // ../1234/xyz

    // path: "/abc/123/xyz/"
    // cwd:  "/abc/123/"
    // xyz
    assert(path[0] == '/');
    const abs_cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(abs_cwd);
    var prev_slash_i: u32 = 0;
    const min_len = @min(path.len, abs_cwd.len);

    for (path[0..min_len], abs_cwd[0..min_len], 0..) |ac, bc, i| {
        if (ac != bc) {
            break;
        } else if (ac == '/') {
            prev_slash_i = @intCast(i);
        }
    }
    var slash_count: u32 = 0;
    var slash_count_until_stop: u32 = 0;
    for (abs_cwd, 0..) |c, i| {
        if (c == '/') {
            slash_count += 1;
            if (i <= prev_slash_i) slash_count_until_stop += 1;
        }
    }
    var step_backward: u32 = slash_count - slash_count_until_stop;
    if (abs_cwd[abs_cwd.len - 1] != '/') step_backward += 1;
    var buf = try allocator.alloc(u8, step_backward * 3 + path.len - prev_slash_i - 1);
    for (0..step_backward) |i| {
        _ = try std.fmt.bufPrint(buf[i * 3 ..], "../", .{});
    }
    _ = try std.fmt.bufPrint(buf[step_backward * 3 ..], "{s}", .{path[prev_slash_i + 1 ..]});
    return buf;
}
fn OpenDirOfFile(file_path: []const u8, cwd: Dir) !Dir {
    return cwd.openDir(GetDirOfPath(file_path), .{});
}

fn GetDirOfPath(file_path: []const u8) []const u8 {
    const last_slash_index = std.mem.lastIndexOfScalar(u8, file_path, '/') orelse return "."; // windows compatiblity?
    return file_path[0..last_slash_index];
}
pub fn SearchFile(allocator: std.mem.Allocator, file: File, queue: *FnQueue, match_ast: *Ast, match_fn: Ast.full.FnProto, dir: *std.heap.FixedBufferAllocator, file_set: *FileSet, depth: u32, dist_limit: u32) !usize {
    const file_size = (file.stat() catch |e| {
        std.log.err("Cannot get file size", .{});
        return e;
    }).size;
    const source = allocator.allocSentinel(u8, file_size, 0) catch |e| {
        std.log.err("failed to allocate {} bytes to read file\n", .{file_size});
        return e;
    };
    var ct: usize = 0;
    defer allocator.free(source);
    _ = try file.readAll(source);
    var ast = try Ast.parse(allocator, source, .zig);
    defer ast.deinit(allocator);
    for (ast.rootDecls()) |d| {
        var buffer: [1]Ast.Node.Index = undefined;
        var fn_proto = ast.fullFnProto(&buffer, d) orelse continue;
        const distance = FuzzyMatchFn(allocator, &ast, match_ast, fn_proto, match_fn);
        ct += 1;
        // std.log.debug("fn {s}() distance: {}", .{ tokenRender(ast, fn_proto.name_token), distance });
        if (distance > dist_limit) continue;
        const fn_result = try allocator.create(FnResult);
        const location = ast.tokenLocation(0, fn_proto.ast.fn_token);
        fn_result.* = .{ .fnString = try FormatFn(allocator, ast, fn_proto), .distance = distance, .location = .{ .file = try RelativePathFromCwd(allocator, dir.buffer[0..dir.end_index]), .line = location.line, .column = location.column } };
        try queue.add(fn_result);
    }
    if (depth == 1) return ct;

    const cwd_path = GetDirOfPath(dir.buffer[0..dir.end_index]);
    dir.end_index = cwd_path.len;
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    std.log.debug("Currently in: {s}", .{cwd_path});
    defer cwd.close();
    for (ast.nodes.items(.tag), 0..) |t, i| {
        switch (t) {
            .builtin_call_two,
            .builtin_call,
            => {
                const token = tokenRender(ast, ast.nodes.items(.main_token)[i]);
                if (std.mem.eql(u8, token, "@import")) {
                    const arg = ast.nodes.items(.data)[i];
                    const file_name_quote = tokenRender(ast, ast.nodes.items(.main_token)[arg.lhs]);
                    const file_name = file_name_quote[1 .. file_name_quote.len - 1];
                    // std.log.debug("@import({s})", .{file_name_quote});
                    if (!std.mem.endsWith(u8, file_name, ".zig")) continue;

                    var next_file = try cwd.openFile(file_name, .{ .mode = .read_only });
                    defer next_file.close();
                    _ = try std.fmt.allocPrint(dir.allocator(), "/{s}", .{file_name});
                    defer dir.end_index = cwd_path.len;
                    // std.log.debug("new dir: {s}", .{dir.buffer[0..dir.end_index]});

                    const inode = (try next_file.stat()).inode;
                    if (file_set.contains(inode)) {
                        continue;
                    } else {
                        try file_set.put(inode, {});
                    }
                    // std.log.debug("Searching next file: {s}", .{file_name});
                    ct += try SearchFile(allocator, next_file, queue, match_ast, match_fn, dir, file_set, depth - 1, dist_limit);
                }
            },
            else => {},
        }
    }
    return ct;
}

pub fn tokenRender(tree: Ast, token_index: ?Ast.TokenIndex) []const u8 {
    if (token_index) |i| {
        return Ast.tokenSlice(tree, i);
    }
    return "";
}
pub fn ParseFuncInline(ast: *Ast, buf: *Ast.Node.Index) !Ast.full.FnProto {
    // ast.fullFnProto(, node: Node.Index)
    for (ast.nodes.items(.tag), 0..) |t, i| {
        _ = t;
        buf.* = @intCast(i);
        return ast.fullFnProto(buf, @intCast(i)) orelse continue;
        // return ast.fullFnProto(&match_fn_node, @intCast(i)) orelse continue;
    }

    return error.InvalidMatchSyntax;
}

pub fn ParseFuncDecl(ast: *Ast, buf: *Ast.Node.Index) !Ast.full.FnProto {
    for (ast.rootDecls()) |d| {
        return ast.fullFnProto(buf, d) orelse continue;
    }
    return error.InvalidMatchSyntax;
}




pub fn FormatFn(allocator: std.mem.Allocator, tree: Ast, fnProto: Ast.full.FnProto) ![]u8 {
    const start = tree.tokens.items(.start)[@intCast(fnProto.name_token.?)];
    const end = tree.tokens.items(.start)[tree.lastToken(fnProto.ast.return_type) + 1];
    const slice = try allocator.alloc(u8, end - start);
    @memcpy(slice, tree.source[start..end]);
    return slice;
}

pub fn ExactMatchType(a_tree: *Ast, b_tree: *Ast, a: Ast.Node.Index, b: Ast.Node.Index) bool {
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
                if (!std.mem.eql(u8, tokenRender(a_tree.*, @intCast(ai)), tokenRender(b_tree.*, @intCast(bi)))) return false;
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

const TokenTag = std.zig.Token.Tag;

fn EqlTag(ctx: ?*anyopaque, a: TokenTag, b: TokenTag) bool {
    _ = ctx;
    return a == b;
}

fn FuzzyMatchType(allocator: std.mem.Allocator, a_tree: *Ast, b_tree: *Ast, a: Ast.Node.Index, b: Ast.Node.Index) u32 {
    const a_first = a_tree.tokens.items(.start)[a_tree.firstToken(a)];
    
        
    
    const a_last = if (a_tree.lastToken(a) + 1 >= a_tree.tokens.len) a_tree.source.len else  a_tree.tokens.items(.start)[a_tree.lastToken(a) + 1];
    const a_param = a_tree.source[a_first..a_last];

    const b_first = b_tree.tokens.items(.start)[b_tree.firstToken(b)];
    const b_last = if (b_tree.lastToken(b) + 1 >= b_tree.tokens.len) b_tree.source.len else  b_tree.tokens.items(.start)[b_tree.lastToken(b) + 1];
    const b_param = b_tree.source[b_first..b_last];
    
    return LevenshteinDistance(allocator, a_param, b_param) catch std.math.maxInt(u32);
}

fn FuzzyCostType(tree: Ast, a: Ast.Node.Index) u32 {
    var d: u32 = 0;
    const last_token = tree.lastToken(a);
    const a_type = tree.tokens.items(.tag)[tree.firstToken(a)..last_token];
    d += @intCast(a_type.len);
    d += @intCast(tokenRender(tree, last_token).len);
    return d;
}

fn FuzzyMatchFn(allocator: std.mem.Allocator, a_tree: *Ast, b_tree: *Ast, a: Ast.full.FnProto, b: Ast.full.FnProto) u32 {
    var dist: u32 = 0;
    if (a.name_token != null and b.name_token != null) {
        dist += (LevenshteinDistance(allocator, tokenRender(a_tree.*, a.name_token), tokenRender(b_tree.*, b.name_token)) catch return std.math.maxInt(u32));
    }
    dist += FuzzyMatchType(allocator, a_tree, b_tree, a.ast.return_type, b.ast.return_type);
    // std.log.debug("return dist: {}", .{dist});
    var ai = a.iterate(a_tree);
    var bi = b.iterate(b_tree);
    while (true) {
        const ap = ai.next();
        const bp = bi.next();
        if (ap == null and bp == null) {
            break;
        } else if (ap == null) {
            dist += FuzzyCostType(b_tree.*, bp.?.type_expr) * 2;
        } else if (bp == null) {
            dist += FuzzyCostType(a_tree.*, ap.?.type_expr) * 2;
        } else {
            const a_name = tokenRender(a_tree.*, ap.?.name_token);
            const b_name = tokenRender(b_tree.*, bp.?.name_token);
            dist += (LevenshteinDistance(allocator, a_name, b_name) catch return std.math.maxInt(u32));
            dist += FuzzyMatchType(allocator, a_tree, b_tree, ap.?.type_expr, bp.?.type_expr);
        }
        // std.log.debug("param dist: {}", .{dist});

    }

    return dist;
}

const OpenError = std.fs.File.OpenError;
const ParseError = error{
    ExpectFileArgument,
    ExpectMatchArgument,
    InvalidMatchSyntax,
    InvalidArgumentOption,
    PacakageNotFound,
};

pub const FnQueue = std.PriorityQueue(*FnResult, ?*anyopaque, FnResult.compare);
const FnResult = struct {
    fnString: []const u8,
    distance: u32,
    location: struct {
        file: []const u8,
        line: usize,
        column: usize,
    },
    const self = @This();
    pub fn compare(ctx: ?*anyopaque, a: *self, b: *self) std.math.Order {
        _ = ctx;
        return std.math.order(a.distance, b.distance);
    }
};

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

fn StdLibrary(lib: []const u8) ![]const u8 {
    if (std.mem.eql(u8, lib, "std")) {
        return "lib/std/std.zig";
    } else if (std.mem.eql(u8, lib, "builtin")) {
        return "lib/std/builtin.zig";
    }
    return error.PacakageNotFound;
}


pub fn Search(allocator: std.mem.Allocator, s: []const u8, path: []const u8, depth: u32) !FnQueue {

    const file_name = path;
    const match_string = try allocator.allocSentinel(u8, s.len, 0);
    @memcpy(match_string, s);
    var dist_limit: u32 = 20;

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
        dist_limit += @intCast(tokenRender(match_ast, nt).len);
    }
    var match_param_it = match_fn.iterate(&match_ast);
    while (match_param_it.next()) |p| {
        if (p.name_token) |nt| {
            dist_limit += @intCast(tokenRender(match_ast, nt).len);
        }
    }
    // try stdout.print("input: {s}\n", .{match_string});
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
    defer file.close();


    try file_set.put(((try file.stat()).inode), {});
    var fn_queue = FnQueue.init(allocator, null);
    const ct = try SearchFile(allocator, file, &fn_queue, &match_ast, match_fn, &path_fba, &file_set, depth, dist_limit);
    _ = ct;
    return fn_queue;


}