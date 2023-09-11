const std = @import("std");
const process = std.process;
const Ast = std.zig.Ast;
const assert = std.debug.assert;
const FileSet = std.AutoHashMap(std.fs.File.INode, void);


const LVDistance = @import("distance.zig");
const LevenshteinDistance = LVDistance.LevenshteinDistance;
const LevenshteinDistanceOptions = LVDistance.LevenshteinDistanceOptions;

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

const TokenTag = std.zig.Token.Tag;

fn EqlTag(ctx: ?*anyopaque, a: TokenTag, b: TokenTag) bool {
    _ = ctx;
    return a == b;
}

fn FuzzyMatchType(
                allocator: std.mem.Allocator, 
                a_tree: *Ast, b_tree: *Ast, 
                a: Ast.Node.Index, b: Ast.Node.Index) 
                u32 {
    const a_type = a_tree.tokens.items(.tag)[a_tree.firstToken(a)..a_tree.lastToken(a)];
    const b_type = b_tree.tokens.items(.tag)[b_tree.firstToken(b)..b_tree.lastToken(b)];
    var d = LevenshteinDistanceOptions(TokenTag)(allocator, a_type, b_type, .{.eql=EqlTag}) catch return std.math.maxInt(u32);
    d += LevenshteinDistance(allocator, tokenRender(a_tree.*, a_tree.lastToken(a)), tokenRender(b_tree.*, b_tree.lastToken(b)))
                                                        catch return std.math.maxInt(u32);
    return d;
}

fn FuzzyCostType(tree: Ast, a: Ast.Node.Index) u32 {
    var d: u32 = 0;
    const last_token = tree.lastToken(a);
    const a_type = tree.tokens.items(.tag)[tree.firstToken(a)..last_token];
    d += @intCast(a_type.len);
    d += @intCast(tokenRender(tree, last_token).len);
    return d;
}

fn FuzzyMatchFn(
                allocator: std.mem.Allocator, 
                a_tree: *Ast, b_tree: *Ast, 
                a: Ast.full.FnProto, b: Ast.full.FnProto) 
                u32 {
    var dist: u32 = 0;
    if (a.name_token != null and b.name_token != null) {
        dist += (LevenshteinDistance(allocator, 
                                    tokenRender(a_tree.*, a.name_token), 
                                    tokenRender(b_tree.*, b.name_token)) catch return std.math.maxInt(u32));
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
        } else if (bp == null ){
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
const ParseError = error {
    ExpectFileArgument,
    ExpectMatchArgument,
    InvalidMatchSyntax,
    InvalidArgumentOption,
};

const FnQueue = std.PriorityQueue(*FnResult, ?*anyopaque, FnResult.compare);
const FnResult = struct {
    fnString: []const u8,
    distance: u32,
    location: []const u8,
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


fn SearchFile(
    allocator: std.mem.Allocator, 
    file: File, 
    queue: *FnQueue, 
    match_ast: *Ast, match_fn: Ast.full.FnProto, 
    dir: *std.heap.FixedBufferAllocator, 
    file_set: *FileSet,
    depth: u32) 
    !void {
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
        std.log.debug("fn {s}() distance: {}", .{tokenRender(ast, fn_proto.name_token), distance});
        if (distance > dist_limit) continue;
        const fn_result = try allocator.create(FnResult);
        const location = ast.tokenLocation(0, fn_proto.ast.fn_token);
        const location_str = std.fmt.allocPrint(allocator, "{s}:{}:{}", .{dir.buffer[0..dir.end_index], location.line, location.column});
        fn_result.* = .{.fnString = try FormatFn(allocator, ast, fn_proto), 
                        .distance = distance, 
                        .location = try location_str
                        };
        try queue.add(fn_result);
    }
    if (depth == 1) return;
    const dir_curr = dir.end_index;
    var temp_dir = try std.fs.openDirAbsolute(dir.buffer[0..dir_curr], .{});
    std.log.debug("Currently in: {s}", .{dir.buffer[0..dir_curr]});
    defer temp_dir.close();
    for (ast.nodes.items(.tag), 0..) |t, i| {
        switch (t) {
            .builtin_call_two,
            .builtin_call, 
            => {
                const token = tokenRender(ast, ast.nodes.items(.main_token)[i]);
                if (std.mem.eql(u8, token, "@import")) {
                    const arg = ast.nodes.items(.data)[i];
                    const file_name_quote = tokenRender(ast, ast.nodes.items(.main_token)[arg.lhs]);
                    const file_name = file_name_quote[1..file_name_quote.len - 1];
                    // std.log.debug("@import({s})", .{file_name});
                    if (std.mem.eql(u8, file_name, "root") or std.mem.eql(u8, file_name, "std") or std.mem.eql(u8, file_name, "builtin")) continue;

                    var next_file = try temp_dir.openFile(file_name, .{.mode = .read_only});
                    defer next_file.close();
                    _ = try std.fmt.allocPrint(dir.allocator(), "/{s}", .{GetDirOfPath(file_name)});
                    defer dir.end_index = dir_curr;
                    // std.log.debug("new dir: {s}", .{dir.buffer[0..dir.end_index]});



                    const inode = (try next_file.stat()).inode;
                    if (file_set.contains(inode)) {
                        continue;
                    } else {
                        try file_set.put(inode, {});
                    }
                    std.log.debug("Searching next file: {s}", .{file_name});
                    try SearchFile(
                        allocator, 
                        next_file, 
                        queue, 
                        match_ast, match_fn, 
                        dir, 
                        file_set,
                        depth - 1);


                }
                
                
            },
            else => {},
        }
    }
}

const dist_limit = 20;
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
    // try stdout.print("input: {s}\n", .{match_string});
    std.log.debug("fn node: {}", .{match_fn_node[0]});
    try PrintFn(match_ast, match_fn);
    var path_buffer = [_]u8{0} ** 1024;
    var path_fba = std.heap.FixedBufferAllocator.init(&path_buffer);


    var file_set = FileSet.init(allocator);
    defer file_set.deinit();
    var file = find_file: {
        if (std.mem.eql(u8, file_name, "std")) {
            const env_paths = std.os.getenv("PATH") orelse unreachable;
            var iterator = std.mem.splitScalar(u8, env_paths, ':');
            while (iterator.next()) |env_path| {
                var temp_dir = std.fs.openDirAbsolute(env_path, .{}) catch continue;
                defer temp_dir.close();
                const std_zig = temp_dir.openFile("lib/std/std.zig", .{.mode = .read_only}) catch continue;
                _ = temp_dir.realpathAlloc(path_fba.allocator(), "lib/std") catch unreachable;
                break :find_file std_zig;
            }
        }
        _ = std.fs.cwd().realpathAlloc(path_fba.allocator(), GetDirOfPath(file_name)) catch |e| {
            std.log.err("Cannot allocate memoery for the abs path where \"{s}\" is located", .{file_name});
            return e;
        };
        break: find_file std.fs.cwd().openFile(file_name, .{.mode = .read_only}) catch |e| {
            std.log.err("Cannot open file: {s}", .{file_name});
            return e;
        };
    };
    try stdout.print("current path: {s}\n", .{path_buffer});
    try bw.flush();

    try file_set.put(((try file.stat()).inode), {});
    var fn_queue = FnQueue.init(allocator, null); 
    defer fn_queue.deinit();
    try stdout.print("recursive depth: {}\n", .{recursive_depth});
    try SearchFile(
        allocator, 
        file, 
        &fn_queue, 
        &match_ast, match_fn, 
        &path_fba, 
        &file_set,
        recursive_depth);

    try stdout.print("opening {s}\n", .{file_name});
    defer file.close();

    
    // var buffer: [1]Ast.Node.Index = undefined;
    try stdout.print("Find {} candidates\n", .{fn_queue.count()});
    while (fn_queue.removeOrNull()) |fr| {
        try stdout.print("{s} {s}\n", .{fr.location, fr.fnString});
        allocator.free(fr.fnString);
        allocator.free(fr.location);
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
