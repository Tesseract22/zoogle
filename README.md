# zoogle
Fuzzy Search for Function in [`Zig`](https://github.com/ziglang/zig)
>  This project is inspired by [Hoogle](https://hoogle.haskell.org/)
Zoogle is a CLI tool for you to fuzzily search for functions in `Zig` by function signature. I am planning on building a web frontend.

## Examples
### Usage
```bash
zoogle $path_to_file $search_string [-r $recursive_depth=1]
   where path_to_file = {"std" | relative_path}
   where search_string = "fn [$fn_name]([$var_name]: $var_type, ...) $var_type"
```
### Searching `std`
```bash
./zig-out/bin/zoogle std "fn hashmp(type, type) type" -r 2 # (misspelling is intentional)
```
 yields:
```
Find 31 candidates
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/enums.zig:267:4 EnumMap(comptime E: type, comptime V: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/math.zig:381:4 Min(comptime A: type, comptime B: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/hash_map.zig:46:4 AutoHashMap(comptime K: type, comptime V: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/enums.zig:722:4 EnumArray(comptime E: type, comptime V: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/array_hash_map.zig:15:4 AutoArrayHashMap(comptime K: type, comptime V: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/meta.zig:106:4 Elem(comptime T: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/meta.zig:665:4 Tag(comptime T: type) type 
../zig-linux-x86_64-0.12.0-dev.278+0e8f130ae/lib/std/mem.zig:674:0 Span(comptime T: type) type
...(More not shown)
```

Provided `std`, `zoogle` automatically search through system `PATH` to find the standard library of Zig. \
The second argument is the function signature. You can optionally include the name of the function and names of the arguments. \
The last `-r 2` set `recursive_depth = 2`. When `zoogle` searches through a file, it also search all the files `@import`ed by that file. With `recursive_depth == 2`, zoogle searches `std.zig`, and all the files `@import`ed by `std.zig`, but not any further.

### Searching regular files ([`zls`](https://github.com/zigtools/zls))
`./zig-out/bin/zoogle ../zls/src/configuration.zig 'fn getConfig(allocator: std.mem.Allocator, []const u8) !Config'` yields

```bash
Find 4 candidates
../zls/src/configuration.zig:73:4 getConfig(allocator: std.mem.Allocator, config_path: ?[]const u8) !ConfigWithPath 
../zls/src/configuration.zig:175:4 findZig(allocator: std.mem.Allocator) !?[]const u8 
../zls/src/configuration.zig:25:4 loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) ?ConfigWithPath 
../zls/src/configuration.zig:119:4 getZigEnv(allocator: std.mem.Allocator, zig_exe_path: []const u8) ?std.json.Parsed(Env) 
```
When `-r` is not specified, zoogle use default value of 1, which only search the provided file.

## Installation && Run
clone and `zig build`, then run `./zig-out/bin/zoogle` to see help.

## TODO
- [x] Searching `std` and `builtin`

~~Searching `@import`ed pacakges by package mamnager~~

- [ ] Searching `fn` declarations in `struct`. (keep in mind that `struct` declaration can take place in `fn` body)
- [ ] Evaluate field access while calculating distance of types, so (`std.mem.Allocator` and `Allocator` become equivalent, somehow). There can be many more funny things to do once we open up the door of field access.
- [ ] Installation through package manager
- [ ] Even-spaced output
- [ ] libzoogle
