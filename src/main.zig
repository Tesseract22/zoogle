const std = @import("std");
const process = std.process;
const Ast = std.zig.Ast;
const assert = std.debug.assert;
const FileSet = std.AutoHashMap(std.fs.File.INode, void);

const LVDistance = @import("distance.zig");
const LevenshteinDistance = LVDistance.LevenshteinDistance;
const LevenshteinDistanceOptions = LVDistance.LevenshteinDistanceOptions;

const Color = @import("color.zig").Color;

const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();
fn tokenRender(tree: Ast, token_index: ?Ast.TokenIndex) []const u8 {
    if (token_index) |i| {
        return Ast.tokenSlice(tree, i);
    }
    return "";
}

fn ParseFuncInline(ast: *Ast, buf: *Ast.Node.Index) !Ast.full.FnProto {
    // ast.fullFnProto(, node: Node.Index)
    for (ast.nodes.items(.tag), 0..) |t, i| {
        _ = t;
        buf.* = @intCast(i);
        return ast.fullFnProto(buf, @intCast(i)) orelse continue;
        // return ast.fullFnProto(&match_fn_node, @intCast(i)) orelse continue;
    }

    return error.InvalidMatchSyntax;
}

fn ParseFuncDecl(ast: *Ast, buf: *Ast.Node.Index) !Ast.full.FnProto {
    for (ast.rootDecls()) |d| {
        return ast.fullFnProto(buf, d) orelse continue;
    }
    return error.InvalidMatchSyntax;
}

fn PrintExpr(writer: anytype, tree: Ast, type_index: Ast.Node.Index) !void {
    const first_token = tree.firstToken(type_index);
    const last_token = tree.lastToken(type_index);
    for (first_token..last_token + 1) |i| {
        _ = try writer.print("{s}", .{tokenRender(tree, @intCast(i))});
    }
}
fn PrintFn(writer: anytype, tree: Ast, fnProto: Ast.full.FnProto) !void {
    if (fnProto.visib_token) |v| {
        try writer.print("{s} ", .{tokenRender(tree, v)});
    }
    try writer.print("fn {s}(", .{tokenRender(tree, fnProto.name_token)});
    var iterator = fnProto.iterate(&tree);
    while (iterator.next()) |param| {
        try writer.print("{s}: ", .{tokenRender(tree, param.name_token)});
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

fn FormatFn(allocator: std.mem.Allocator, tree: Ast, fnProto: Ast.full.FnProto) ![]u8 {
    const start = tree.tokens.items(.start)[@intCast(fnProto.name_token.?)];
    const end = tree.tokens.items(.start)[tree.lastToken(fnProto.ast.return_type) + 1];
    const slice = try allocator.alloc(u8, end - start);
    @memcpy(slice, tree.source[start..end]);
    return slice;
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

const u32Max = std.math.maxInt(u32);

const Context = struct {
    const Index = Ast.TokenIndex;
    const Self = @This();
    s_tree: *Ast,
    t_tree: *Ast,
    s_start: Index,
    t_start: Index,
    s_curr: Index,
    t_curr: Index,
    allocator: *const std.mem.Allocator,
    pub fn init(s_start: Index, t_start: Index,s_tree: *Ast,t_tree: *Ast, allocator: *const std.mem.Allocator) Context {
        return .{.s_tree = s_tree, .t_tree = t_tree, .s_start = s_start, .t_start = t_start, .s_curr = s_start, .t_curr = t_start, .allocator = allocator};
    }
    pub fn cost(tree: *Ast, i: ?Index) u32 {
        if (i) |index| {
            if (tree.tokens.items(.tag)[index] == .identifier) {
                return @intCast(tree.tokenSlice(index).len);
            }
            return 1;
        }
        return 0;
    }
    pub fn dist(ctx: *Self, s: ?Index, t: ?Index) u32 {
        if (s == null) {
            return cost(ctx.t_tree, t);
        }
        if (t == null) {
            return cost(ctx.s_tree, s);
        }
        const si = s.?;
        const ti = t.?;
        const s_tag = ctx.s_tree.tokens.items(.tag)[si];
        const t_tag = ctx.t_tree.tokens.items(.tag)[ti];
        if (s_tag == .identifier and t_tag == .identifier) {
            return LevenshteinDistance(ctx.allocator.*, ctx.s_tree.tokenSlice(si), ctx.t_tree.tokenSlice(ti)) catch u32Max;
        }
        return if (s_tag == t_tag) 1 else 0;
    }
    pub fn nextT(ctx: *Self) ?Index {
        defer ctx.t_curr += 1;
        return ctx.t_curr;
    }
    pub fn nextS(ctx: *Self) ?Index {
        defer ctx.s_curr += 1;
        return ctx.s_curr;
    }
    pub fn resetT(ctx: *Self) void {
        ctx.t_curr = ctx.t_start;
    }
};
const NodeIndexArr = std.ArrayList(Ast.Node.Index);
fn FuzzyMatchType(allocator: std.mem.Allocator, a_tree: *Ast, b_tree: *Ast, a: Ast.Node.Index, b: Ast.Node.Index) u32 {

    const Index = Ast.TokenIndex;

    const a_first = a_tree.firstToken(a);
    const a_len = a_tree.lastToken(a) - a_first + 1;
    const b_first = b_tree.firstToken(b);
    const b_len = b_tree.lastToken(b) - b_first + 1;
    var ctx = Context.init(a_first, b_first, a_tree, b_tree, &allocator);
    return LevenshteinDistanceOptions(Index, Context)
            (allocator, a_len, b_len, 
            &ctx, .{.dist = Context.dist, .nextT = Context.nextT, .nextS = Context.nextS, .resetT = Context.resetT}) catch u32Max;
    
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

const FnQueue = std.PriorityQueue(*FnResult, ?*anyopaque, FnResult.compare);
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
const File = std.fs.File;
const Dir = std.fs.Dir;

fn OpenDirOfFile(file_path: []const u8, cwd: Dir) !Dir {
    return cwd.openDir(GetDirOfPath(file_path), .{});
}

fn GetDirOfPath(file_path: []const u8) []const u8 {
    const last_slash_index = std.mem.lastIndexOfScalar(u8, file_path, '/') orelse return "."; // windows compatiblity?
    return file_path[0..last_slash_index];
}

fn PrintUsage() void {
    std.debug.print("zoogle $path_to_file $search_string [-r $recursive_depth]\n", .{});
    std.debug.print("{s: >8} path_to_file = {{\"std\" | relative_path}}\n", .{"where"});
    std.debug.print("{s: >8} search_string = \"fn [$fn_name]([$var_name]: $var_type, ...) $var_type\"\n", .{"where"});
}

fn SearchFile(allocator: std.mem.Allocator, file: File, queue: *FnQueue, match_ast: *Ast, match_fn: Ast.full.FnProto, dir: *std.heap.FixedBufferAllocator, file_set: *FileSet, depth: u32) !void {
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
    var ast = try Ast.parse(allocator, source, .zig);
    defer ast.deinit(allocator);
    for (ast.rootDecls()) |d| {
        var buffer: [1]Ast.Node.Index = undefined;
        var fn_proto = ast.fullFnProto(&buffer, d) orelse continue;
        const distance = FuzzyMatchFn(allocator, &ast, match_ast, fn_proto, match_fn);
        std.log.debug("fn {s}() distance: {}", .{ tokenRender(ast, fn_proto.name_token), distance });
        if (distance > dist_limit) continue;
        const fn_result = try allocator.create(FnResult);
        const location = ast.tokenLocation(0, fn_proto.ast.fn_token);
        fn_result.* = .{ .fnString = try FormatFn(allocator, ast, fn_proto), .distance = distance, .location = .{ .file = try RelativePathFromCwd(allocator, dir.buffer[0..dir.end_index]), .line = location.line, .column = location.column } };
        try queue.add(fn_result);
    }
    if (depth == 1) return;

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
                    std.log.debug("@import({s})", .{file_name_quote});
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
                    std.log.debug("Searching next file: {s}", .{file_name});
                    try SearchFile(allocator, next_file, queue, match_ast, match_fn, dir, file_set, depth - 1);
                }
            },
            else => {},
        }
    }
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

var dist_limit: u32 = 20;
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
    var match_fn_node: Ast.Node.Index = undefined;
    const match_fn = try ParseFuncInline(&match_ast, &match_fn_node);

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
    // std.log.debug("fn node: {}", .{match_fn_node[0]});
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
    var fn_queue = FnQueue.init(allocator, null);
    defer fn_queue.deinit();
    try stdout.print("recursive depth: {}\n", .{recursive_depth});
    try SearchFile(allocator, file, &fn_queue, &match_ast, match_fn, &path_fba, &file_set, recursive_depth);

    try stdout.print("opening {s}\n", .{file_name});
    defer file.close();

    // var buffer: [1]Ast.Node.Index = undefined;
    try stdout.print("Find {} candidates\n", .{fn_queue.count()});
    while (fn_queue.removeOrNull()) |fr| {
        try stdout.print("{s}{s}:{}:{}{s} {s}{s}{s}\n", .{ Color.KYEL, fr.location.file, fr.location.line, fr.location.column, Color.KRST, Color.KCYN, fr.fnString, Color.KRST });
        // const rel_path = RelativePathFromCwd(allocator, fr.)
        allocator.free(fr.fnString);
        allocator.free(fr.location.file);
        allocator.destroy(fr);
    }

    // _ = token_tags;
    try bw.flush();
    // debugAst(match_ast);

}

fn add(a: i32, b: i32) i32 {
    return a + b;
}

fn debugAst(ast: Ast) void {
    const debug = std.debug.print;
    debug("[{}]Nodes\n", .{ast.nodes.len});
    for (ast.nodes.items(.tag), 0..) |t, i| {
        debug("[{}]: {} = \"{s}\"\n", .{ i, t, tokenRender(ast, ast.nodes.items(.main_token)[i]) });
    }
    // try stdout.print("token tags:\n", .{});
    debug("[{}]Tokens", .{ast.tokens.len});
    for (ast.tokens.items(.tag), 0..) |t, i| {
        if (t == .invalid) break;
        debug("[{}]: {} = \"{s}\"\n", .{ i, t, tokenRender(ast, @intCast(i)) });
    }
}



var ta = std.testing.allocator;

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
    const fn_proto = try ParseFuncDecl(&ast, &buf);

    const match_fn_str = "fn split(type, []const T, []const T) SplitIterator";
    var match_ast = try Ast.parse(ta, match_fn_str, .zig);
    defer match_ast.deinit(ta);
    var match_buf: Ast.Node.Index = undefined;
    const match_fn_proto = try ParseFuncInline(&match_ast, &match_buf);

    std.debug.print("\n{}\n", .{fn_proto});
    debugAst(ast);
    try PrintFn(stderr, ast, fn_proto);

    std.debug.print("\n{}\n", .{match_fn_proto});
    debugAst(match_ast);
    try PrintFn(stderr, match_ast, match_fn_proto);
    var t1 = std.time.microTimestamp();
    const return_dist1 = FuzzyMatchType(ta, &match_ast, &ast, match_fn_proto.ast.return_type, fn_proto.ast.return_type);
    t1 = std.time.microTimestamp() - t1;
    std.debug.print("FuzzyMatchType(return_type) => {}, {} microseconds ({})ms\n", .{return_dist1, t1});
    
    // const ta = std.heap.testAllocator(st)
}






