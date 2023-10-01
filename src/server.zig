const std = @import("std");

const Server = std.http.Server;
const addr = std.net.Address.parseIp("127.0.0.1", 8080) catch @compileError("Invalid Addr");
const Zoogle = @import("zoogle.zig");

const cwd = std.fs.cwd();

fn serveFile(writer: std.http.Server.Response.Writer, f: std.fs.File) !void {
    var buf: [1024]u8 = undefined;
    var size: usize = undefined;
    var total: usize = 0;
    while (true) {
        size = try f.read(&buf);
        if (size == 0) return;
        total += size;
        std.debug.print("total: {}\n", .{total});
        _ = try writer.write(buf[0..size]);
    }
}


const HTTP_VERSION = "HTTP/1.1";
const MSG = "Hello From Zig!\n";


pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var server = Server.init(allocator, .{.kernel_backlog = 10, .reuse_address = true, .reuse_port = true});
    defer server.deinit();
    try server.listen(addr);

    std.debug.print("Server running at 127.0.0.1:8080\n", .{});
    while (true) {
        var request = try server.accept(.{.allocator = allocator});
        defer request.deinit();
        try request.wait();
        std.debug.print("{} {} {s}\n", .{request.request.version, request.request.method, request.request.target});
        std.debug.print("STATUS: {}\n", .{request.status});
        


        if (std.mem.eql(u8, request.request.target, "/")) {


            var f = try cwd.openFile("index/index.html", .{.mode = .read_only});
            defer f.close();
            const size = (try f.stat()).size;
            var buf: [256]u8 = undefined;
            const len_buf = try std.fmt.bufPrint(&buf, "{}", .{size});
            try request.headers.append("Content-Length", len_buf);
            try request.headers.append("Content-Type", "Content-Type: text/html; charset=utf-8");
            request.status = .ok;
            try request.do();
            std.debug.print("{}\n", .{request.transfer_encoding});
            try serveFile(request.writer(), f);
        } 
        else if (std.mem.eql(u8, request.request.target, "/search") and request.request.method == .POST) {
            // try request.headers.append("Content-Length", len_buf);
            // try request.headers.append("Content-Type", "Content-Type: text/html; charset=utf-8");
            var buf = [_]u8{0} ** 1024;
            const read_bytes = try request.read(&buf);
            std.debug.print("read: {} {s}\n", .{read_bytes, buf[0..read_bytes]});
            
            var q = Zoogle.Search(allocator, buf[0..read_bytes], "std", 2) catch |e| {
                std.debug.print("Search error: {}\n", .{e});
                request.transfer_encoding = .{.content_length = 0};
                request.status = .bad_request;
                try request.do();
                try request.finish();
                continue;
            };
            defer q.deinit();
            var it = q.iterator();
            var len: usize = 0;
            while (it.next()) |f| {
                len += f.fnString.len + 1;
            }

            
            request.transfer_encoding = .{.content_length = len};
            const len_buf = try std.fmt.bufPrint(&buf, "{}", .{len});
            try request.headers.append("Content-Length", len_buf);
            try request.headers.append("Content-Type", "text/html; charset=utf-8");
            request.status = .ok;
            try request.do();

            while (q.removeOrNull()) |f| {
                _ = try request.write(f.fnString);
                _ = try request.write("\n");
                allocator.free(f.fnString);
                allocator.free(f.location.file);
                allocator.destroy(f);
            }

        }
        else {
            request.transfer_encoding = .{.content_length = 0};
            request.status = .not_found;
            try request.do();
            
        }
        try request.finish();
    }

}