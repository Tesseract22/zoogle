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
pub fn DistanceOptions(comptime T: type, comptime CT: type) type {
    return struct {
        dist: fn (ctx: *CT, s: ?T, t: ?T) u32, // only positive distance is supported. The optional null tpye is for the 'zero' element
        nextT: fn(ctx: *CT) ?T,
        nextS: fn(ctx: *CT) ?T,
        resetT: fn(ctx: *CT) void,
    };
}

const Error = std.mem.Allocator.Error;
pub fn LevenshteinDistanceOptions(comptime T: type, comptime CT: type) (fn (std.mem.Allocator, usize, usize, *CT, DistanceOptions(T, CT)) Error!u32) {
    return struct {
        pub fn f(allocator: std.mem.Allocator, s_len: usize, t_len: usize, ctx: *CT, comptime options: DistanceOptions(T, CT)) Error!u32 {
            const m = s_len;
            const n = t_len;

            var v0 = try allocator.alloc(u32, n + 1);
            var v1 = try allocator.alloc(u32, n + 1);
            defer allocator.free(v0);
            defer allocator.free(v1);
            for (0..n + 1) |i| {
                v0[i] = @intCast(i);
            }
            for (0..m) |i| {
                const s = options.nextS(ctx) orelse unreachable;
                v1[0] = @as(u32, @intCast(i)) + 1;
                for (0..n) |j| {
                    const t = options.nextT(ctx) orelse unreachable;
                    const deletionCost = v0[j + 1] + options.dist(ctx, s, null);
                    const insertionCost = v1[j] + options.dist(ctx, null, t);
                    const substitutionCost = v0[j] + options.dist(ctx, s, t);
                    v1[j + 1] = @min(deletionCost, @min(insertionCost, substitutionCost));
                }
                var tmp = v0;
                v0 = v1;
                v1 = tmp;
                options.resetT(ctx);
                // swap
            }
            return v0[n];
        }
    }.f;
}

fn TestDistance(s: []const u8, t: []const u8, expect: u32) !void {
    const d = try LevenshteinDistance(std.testing.allocator, s, t);
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

fn u8Eql(a: u8, b: u8) bool {
    return a == b;
}

// test "distance options" {
//     const d = try LevenshteinDistanceOptions(u8)(std.testing.allocator, "hello", "hllo", .{ .eql = u8Eql });
//     std.debug.print("distance: {}\n", .{d});
// }
