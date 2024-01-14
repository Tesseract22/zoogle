const std = @import("std");

pub fn LevenshteinDistance(allocator: std.mem.Allocator, s: []const u8, t: []const u8) !u32 {
    const m = s.len;
    const n = t.len;

    var v0 = try allocator.alloc(u32, n + 1);
    var v1 = try allocator.alloc(u32, n + 1);
    defer allocator.free(v0);
    defer allocator.free(v1);
    for (0..n + 1) |i| {
        v0[i] = @intCast(i);
    }
    for (0..m) |i| {
        v1[0] = @as(u32, @intCast(i)) + 1;
        for (0..n) |j| {
            const deletionCost = v0[j + 1] + 1;
            const insertionCost = v1[j] + 1;
            var substitutionCost: u32 = undefined;
            if (s[i] == t[j]) {
                substitutionCost = v0[j];
            } else {
                substitutionCost = v0[j] + 1;
            }
            v1[j + 1] = @min(deletionCost, @min(insertionCost, substitutionCost));
        }
        var tmp = v0;
        v0 = v1;
        v1 = tmp;
        // swap
    }
    return v0[n];
}


pub fn LevenshteinDistanceOptions(ctx: anytype, allocator: std.mem.Allocator) !u32 {
    const m = ctx.s_len;
    const n = ctx.t_len;
    const C = @TypeOf(ctx.*);
    var v0 = try allocator.alloc(u32, n + 1);
    var v1 = try allocator.alloc(u32, n + 1);
    defer allocator.free(v0);
    defer allocator.free(v1);
    v0[0] = 0;
    var delete_acc: u32 = 0;
    // that distance is the number of characters to append to  s to make t.
    for (1..n + 1) |i| {
        v0[i] = v0[i-1] + ctx.cost(C.zero, ctx.nextT());
    }
    // std.debug.print("m: {}, n: {}\n", .{m, n});
    // std.debug.print("vo start: {any}\n", .{v0});
    ctx.resetT();
    for (0..m) |i| {
        _ = i;
        // edit distance is delete (i + 1) chars from s to match empty t
        const s = ctx.nextS();
        delete_acc += ctx.cost(s, C.zero);
        v1[0] = delete_acc;
        // std.debug.print("i={}, v1: {any}\n", .{i, v0});
        for (0..n) |j| {
            const t = ctx.nextT();
            // std.debug.print("s[{}]={s}, t[{}]={s}\n", .{s,ctx.ast_s.tokenSlice(s),t,ctx.ast_t.tokenSlice(t)});
            const deletionCost = v0[j + 1] + ctx.cost(C.zero, t);
            const insertionCost = v1[j] + ctx.cost(s, C.zero);
            const substitutionCost = v0[j] + ctx.cost(s, t);
            // std.debug.print("({}, {}, {})\n", .{deletionCost, insertionCost, substitutionCost});
            v1[j + 1] = @min(deletionCost, @min(insertionCost, substitutionCost));
        }
        ctx.resetT();
        var tmp = v0;
        v0 = v1;
        v1 = tmp;
        // swap
    }
    return v0[n];
}

fn TestDistance(s: []const u8, t: []const u8, expect: u32) !void {
    const d = try LevenshteinDistance(std.testing.allocator, s, t);
    std.debug.print("({s: <15} => {s: >15}) => ({: <2} <=> {: >2})\n", .{ s, t, expect, d });
    try std.testing.expect(d == expect);
}
const Ctx = struct {
    const zero = 0;
    s: []const u8,
    t: []const u8,
    si: usize = 0,
    ti: usize = 0,
    s_len: usize = 0,
    t_len: usize = 0,
    pub fn cost(self: Ctx, s: u8, t: u8) u32 {
        _ = self;
        return @intFromBool(s != t);
    }
    pub fn nextS(self: *Ctx) u8 {
        defer self.si += 1;
        return self.s[self.si];
    }
    pub fn nextT(self: *Ctx) u8 {
        defer self.ti += 1;
        return self.t[self.ti];
    }
    pub fn resetT(self: *Ctx) void {
        self.ti = 0;
    }
};
fn TestDistanceOpt(s: []const u8, t: []const u8, expect: u32) !void {
    var ctx = Ctx{.s = s, .t = t, .s_len = s.len, .t_len = t.len};
    const d = try LevenshteinDistanceOptions(&ctx, std.testing.allocator);
    std.debug.print("({s: <15} => {s: >15}) => ({: <2} <=> {: >2})\n", .{ s, t, expect, d });
    try std.testing.expect(d == expect);
}

test "distance" {
    std.debug.print("\n", .{});
    try TestDistance("kitten", "sitting", 3);
    try TestDistance("hello", "hello", 0);
    try TestDistance("hello", "hello world", 6);
    try TestDistance("hello", "hllo", 1);
    try TestDistance("asfl;asvma;sd", "asfa[od; m", 8);
}

test "distance option" {
    std.debug.print("\n", .{});
    try TestDistanceOpt("sitting", "", 7);
    try TestDistanceOpt("hello", "hello", 0);
    try TestDistanceOpt("hello", "hello world", 6);
    try TestDistanceOpt("hello", "hllo", 1);
    try TestDistanceOpt("asfl;asvma;sd", "asfa[od; m", 8);
}
