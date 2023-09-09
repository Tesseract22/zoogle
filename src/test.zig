const std = @import("std");
pub fn add(a: i32, b: i32) []i32 {
    try std.io.getStdOut().write("add");
    return a + b;
}

pub fn main() !void {
    std.debug.print("{} + {} = {}\n", .{5, 10, (try add(5, 10)).?});
}