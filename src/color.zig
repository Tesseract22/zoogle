const std = @import("std");
const builtin = @import("builtin");
pub fn ColorGen() type {
    switch (builtin.os.tag) {
        .linux,
        .macos,
        => return struct {
            pub const KNRM = "\x1B[0m";
            pub const KRED = "\x1B[31m";
            pub const KGRN = "\x1B[32m";
            pub const KYEL = "\x1B[33m";
            pub const KBLU = "\x1B[34m";
            pub const KMAG = "\x1B[35m";
            pub const KCYN = "\x1B[36m";
            pub const KWHT = "\x1B[37m";
            pub const KRST = "\x1B[0m";
        },
        else => return struct {
            pub const KNRM = "";
            pub const KRED = "";
            pub const KGRN = "";
            pub const KYEL = "";
            pub const KBLU = "";
            pub const KMAG = "";
            pub const KCYN = "";
            pub const KWHT = "";
            pub const KRST = "";
        },
    }
}


pub const Color = ColorGen();


test "color" {
    std.debug.print("{s} RED {s}\n", .{Color.KRED, Color.KRST});
}