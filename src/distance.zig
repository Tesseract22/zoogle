const std = @import("std");

pub fn LevenshteinDistance(allocator: std.mem.Allocator, s: []const u8, t: []const u8) !usize {
    const m = s.len;
    const n = t.len;

    var v0 = try allocator.alloc(usize, n + 1);
    var v1 = try allocator.alloc(usize, n + 1);
    defer allocator.free(v0);
    defer allocator.free(v1);
    for (0..n + 1) |i| {
        v0[i] = @intCast(i);
    }
    for (0..m) |i| {
        v1[0] = @as(usize, @intCast(i)) + 1;
        for (0..n) |j| {
            const deletionCost = v0[j + 1] + 1;
            const insertionCost = v1[j] + 1;
            var substitutionCost: usize = undefined;
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


pub fn LevenshteinDistanceOptions(ctx: anytype, allocator: std.mem.Allocator) !usize {
    const C = @TypeOf(ctx.*);
    var v0 = std.ArrayList(usize).init(allocator);
    var v1 = std.ArrayList(usize).init(allocator);
    defer v0.deinit();
    defer v1.deinit();

    try v0.append(0);
    while (ctx.nextT()) |t| {
        try v0.append(v0.getLast() + ctx.cost(C.zero, t));
    }
    _ = try v1.addManyAsSlice(v0.items.len);
    var delete_acc: usize = 0;
    var i: usize = 0;
    while (ctx.nextS()) |s|: (i += 1) {
        // edit distance is delete (i + 1) chars from s to match empty t
        delete_acc += ctx.cost(s, C.zero);
        v1.items[0] = delete_acc;
        var j: usize = 0;
        ctx.resetT();
        while (ctx.nextT()) |t|: (j += 1) {
            // std.debug.print("{} {} {} {}", .{i, j, s, t});
            const deletionCost = v0.items[j + 1] + ctx.cost(C.zero, t);
            const insertionCost = v1.items[j] + ctx.cost(s, C.zero);
            const substitutionCost = v0.items[j] + ctx.cost(s, t);
            // std.debug.print("{} {} {}\n", .{deletionCost, insertionCost, substitutionCost});
            v1.items[j + 1] = @min(deletionCost, @min(insertionCost, substitutionCost));
        }
        std.mem.swap(std.ArrayList(usize), &v1, &v0);
        // swap
    }
    return v0.getLast();
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
    pub fn cost(self: Ctx, s: u8, t: u8) u32 {
        _ = self;
        return @intFromBool(s != t);
    }
    pub fn nextS(self: *Ctx) ?u8 {
        if (self.si >= self.s.len) return null;
        defer self.si += 1;
        return self.s[self.si];
    }
    pub fn nextT(self: *Ctx) ?u8 {
        if (self.ti >= self.t.len) return null;
        defer self.ti += 1;
        return self.t[self.ti];
    }

    pub fn resetS(self: *Ctx) void {
        self.si = 0;
    }
    pub fn resetT(self: *Ctx) void {
        self.ti = 0;
    }
};
fn TestDistanceOpt(s: []const u8, t: []const u8, expect: u32) !void {
    var ctx = Ctx{.s = s, .t = t};
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
    try TestDistance("hello", "hello", 0);
    try TestDistanceOpt("hello", "hello world", 6);
    try TestDistanceOpt("hello", "hllo", 1);
    try TestDistanceOpt("asfl;asvma;sd", "asfa[od; m", 8);
}
