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
pub fn DistanceOptions(comptime T: type) type {
    return struct {
        deletion: u32 = 1,
        insertion: u32 = 1,
        substitution: u32 = 1,
        eql: fn (?*anyopaque, T, T) bool,
        ctx: ?*anyopaque = null,
    };
}

const Error = std.mem.Allocator.Error;
pub fn LevenshteinDistanceOptions(comptime T: type) (fn (std.mem.Allocator, []const T, []const T, DistanceOptions(T)) Error!u32) {
    return struct {
        pub fn f(allocator: std.mem.Allocator, s: []const T, t: []const T, comptime options: DistanceOptions(T)) Error!u32 {
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
                    if (options.eql(options.ctx, s[i], t[j])) {
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

test "distance options" {
    const d = try LevenshteinDistanceOptions(u8)(std.testing.allocator, "hello", "hllo", .{ .eql = u8Eql });
    std.debug.print("distance: {}\n", .{d});
}
