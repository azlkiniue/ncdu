// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const util = @import("util.zig");
const sink = @import("sink.zig");
const ui = @import("ui.zig");
const bin_export = @import("bin_export.zig");

const CborMajor = bin_export.CborMajor;
const ItemKey = bin_export.ItemKey;

// Two ways to read a bin export:
//
// 1. Streaming import
//   - Read blocks sequentially, assemble items into model.Entry's and stitch
//     them together on the go.
//   - Does not use the sink.zig API, since sub-level items are read before their parent dirs.
//   - Useful when:
//     - User attempts to do a refresh or delete while browsing a file through (2)
//     - Reading from a stream
//
// 2. Random access browsing
//   - Read final block first to get the root item, then have browser.zig fetch
//     dir listings from this file.
//   - The default reader mode, requires much less memory than (1) and provides
//     a snappier first-browsing experience.
//
// The approach from (2) can also be used to walk through the entire directory
// tree and stream it to sink.zig (either for importing or converting to JSON).
// That would allow for better code reuse and low-memory conversion, but
// performance will not be as good as a direct streaming read. Needs
// benchmarks.
//
// This file only implements (2) at the moment.

pub const global = struct {
    var fd: std.fs.File = undefined;
    var index: []u8 = undefined;
    var blocks: [8]Block = [1]Block{.{}}**8;
    var counter: u64 = 0;
};


const Block = struct {
    num: u32 = std.math.maxInt(u32),
    last: u64 = 0,
    data: []u8 = undefined,
};


inline fn bigu16(v: [2]u8) u16 { return std.mem.bigToNative(u16, @bitCast(v)); }
inline fn bigu32(v: [4]u8) u32 { return std.mem.bigToNative(u32, @bitCast(v)); }
inline fn bigu64(v: [8]u8) u64 { return std.mem.bigToNative(u64, @bitCast(v)); }

fn die(comptime s: []const u8, arg: anytype) noreturn {
    ui.die("Error reading from file: "++s++"\n", arg);
}


fn readBlock(num: u32) []const u8 {
    // Simple linear search, only suitable if we keep the number of in-memory blocks small.
    var block: *Block = &global.blocks[0];
    for (&global.blocks) |*b| {
        if (b.num == num) {
            if (b.last != global.counter) {
                global.counter += 1;
                b.last = global.counter;
            }
            return b.data;
        }
        if (block.last > b.last) block = b;
    }
    if (block.num != std.math.maxInt(u32))
        main.allocator.free(block.data);
    block.num = num;
    global.counter += 1;
    block.last = global.counter;

    if (num > global.index.len/8 - 1) die("invalid reference to block {}", .{num});
    const offlen = bigu64(global.index[num*8..][0..8].*);
    if ((offlen & 0xffffff) < 16) die("block {} is missing or too small", .{num});

    const buf = main.allocator.alloc(u8, (offlen & 0xffffff) - 12) catch unreachable;
    defer main.allocator.free(buf);
    const rdlen = global.fd.preadAll(buf, (offlen >> 24) + 8)
        catch |e| die("{s}", .{ui.errorString(e)});
    if (rdlen != buf.len) die("short read for block {}", .{num});

    const rawlen = bigu32(buf[0..4].*);
    if (rawlen >= (1<<24)) die("too large uncompressed size for {}", .{num});
    block.data = main.allocator.alloc(u8, rawlen) catch unreachable;

    // TODO: decompress
    @memcpy(block.data, buf[4..][0..rawlen]);
    return block.data;
}


const CborReader = struct {
    buf: []const u8,

    fn head(r: *CborReader) !CborVal {
        if (r.buf.len < 0) return error.EndOfStream;
        var v = CborVal{
            .rd = r,
            .major = @enumFromInt(r.buf[0] >> 5),
            .indef = false,
            .arg = 0,
        };
        switch (r.buf[0] & 0x1f) {
            0x00...0x17 => |n| {
                v.arg = n;
                r.buf = r.buf[1..];
            },
            0x18 => {
                if (r.buf.len < 2) return error.EndOfStream;
                v.arg = r.buf[1];
                r.buf = r.buf[2..];
            },
            0x19 => {
                if (r.buf.len < 3) return error.EndOfStream;
                v.arg = bigu16(r.buf[1..3].*);
                r.buf = r.buf[3..];
            },
            0x1a => {
                if (r.buf.len < 5) return error.EndOfStream;
                v.arg = bigu32(r.buf[1..5].*);
                r.buf = r.buf[5..];
            },
            0x1b => {
                if (r.buf.len < 9) return error.EndOfStream;
                v.arg = bigu64(r.buf[1..9].*);
                r.buf = r.buf[9..];
            },
            0x1f => switch (v.major) {
                .bytes, .text, .array, .map, .simple => {
                    v.indef = true;
                    r.buf = r.buf[1..];
                },
                else => return error.Invalid,
            },
            else => return error.Invalid,
        }
        return v;
    }

    // Read the next CBOR value, skipping any tags
    fn next(r: *CborReader) !CborVal {
        while (true) {
            const v = try r.head();
            if (v.major != .tag) return v;
        }
    }
};

const CborVal = struct {
    rd: *CborReader,
    major: CborMajor,
    indef: bool,
    arg: u64,

    fn end(v: *const CborVal) bool {
        return v.major == .simple and v.indef;
    }

    fn int(v: *const CborVal, T: type) !T {
        switch (v.major) {
            .pos => return std.math.cast(T, v.arg) orelse return error.IntegerOutOfRange,
            .neg => {
                if (std.math.minInt(T) == 0) return error.IntegerOutOfRange;
                if (v.arg > std.math.maxInt(T)) return error.IntegerOutOfRange;
                return -@as(T, @intCast(v.arg)) + (-1);
            },
            else => return error.InvalidValue,
        }
    }

    // Read either a byte or text string.
    // Doesn't validate UTF-8 strings, doesn't support indefinite-length strings.
    fn bytes(v: *const CborVal) ![]const u8 {
        if (v.indef or (v.major != .bytes and v.major != .text)) return error.InvalidValue;
        if (v.rd.buf.len < v.arg) return error.EndOfStream;
        defer v.rd.buf = v.rd.buf[v.arg..];
        return v.rd.buf[0..v.arg];
    }

    // Skip current value.
    fn skip(v: *const CborVal) !void {
        // indefinite-length bytes, text, array or map; skip till break marker.
        if (v.major != .simple and v.indef) {
            while (true) {
                const n = try v.rd.next();
                if (n.end()) return;
                try n.skip();
            }
        }
        switch (v.major) {
            .bytes, .text => {
                if (v.rd.buf.len < v.arg) return error.EndOfStream;
                v.rd.buf = v.rd.buf[v.arg..];
            },
            .array => {
                for (0..v.arg) |_| try (try v.rd.next()).skip();
            },
            .map => {
                for (0..v.arg*|2) |_| try (try v.rd.next()).skip();
            },
            else => {},
        }
    }

    fn etype(v: *const CborVal) !model.EType {
        const n = try v.int(i32);
        return std.meta.intToEnum(model.EType, n)
            catch if (n < 0) .pattern else .nonreg;
    }

    fn itemref(v: *const CborVal, cur: u64) !u64 {
        if (v.major == .pos) return v.arg;
        if (v.major == .neg) {
            if (v.arg > (1<<24)) return error.InvalidBackReference;
            return cur - v.arg - 1;
        }
        return error.InvalidReference;
    }
};


test "CBOR int parsing" {
    inline for (.{
        .{ .in = "\x00", .t = u1, .exp = 0 },
        .{ .in = "\x01", .t = u1, .exp = 1 },
        .{ .in = "\x18\x18", .t = u8, .exp = 0x18 },
        .{ .in = "\x18\xff", .t = u8, .exp = 0xff },
        .{ .in = "\x19\x07\xff", .t = u64, .exp = 0x7ff },
        .{ .in = "\x19\xff\xff", .t = u64, .exp = 0xffff },
        .{ .in = "\x1a\x00\x01\x00\x00", .t = u64, .exp = 0x10000 },
        .{ .in = "\x1b\x7f\xff\xff\xff\xff\xff\xff\xff", .t = i64, .exp = std.math.maxInt(i64) },
        .{ .in = "\x1b\xff\xff\xff\xff\xff\xff\xff\xff", .t = u64, .exp = std.math.maxInt(u64) },
        .{ .in = "\x1b\xff\xff\xff\xff\xff\xff\xff\xff", .t = i65, .exp = std.math.maxInt(u64) },
        .{ .in = "\x20", .t = i1, .exp = -1 },
        .{ .in = "\x38\x18", .t = i8, .exp = -0x19 },
        .{ .in = "\x39\x01\xf3", .t = i16, .exp = -500 },
        .{ .in = "\x3a\xfe\xdc\xba\x97", .t = i33, .exp = -0xfedc_ba98 },
        .{ .in = "\x3b\x7f\xff\xff\xff\xff\xff\xff\xff", .t = i64, .exp = std.math.minInt(i64) },
        .{ .in = "\x3b\xff\xff\xff\xff\xff\xff\xff\xff", .t = i65, .exp = std.math.minInt(i65) },
    }) |t| {
        var r = CborReader{.buf = t.in};
        try std.testing.expectEqual(@as(t.t, t.exp), (try r.next()).int(t.t));
        try std.testing.expectEqual(0, r.buf.len);
    }
    var r = CborReader{.buf="\x02"};
    try std.testing.expectError(error.IntegerOutOfRange, (try r.next()).int(u1));
    r.buf = "\x18";
    try std.testing.expectError(error.EndOfStream, r.next());
    r.buf = "\x1e";
    try std.testing.expectError(error.Invalid, r.next());
    r.buf = "\x1f";
    try std.testing.expectError(error.Invalid, r.next());
}

test "CBOR string parsing" {
    var r = CborReader{.buf="\x40"};
    try std.testing.expectEqualStrings("", try (try r.next()).bytes());
    r.buf = "\x45\x00\x01\x02\x03\x04x";
    try std.testing.expectEqualStrings("\x00\x01\x02\x03\x04", try (try r.next()).bytes());
    try std.testing.expectEqualStrings("x", r.buf);
    r.buf = "\x78\x241234567890abcdefghijklmnopqrstuvwxyz-end";
    try std.testing.expectEqualStrings("1234567890abcdefghijklmnopqrstuvwxyz", try (try r.next()).bytes());
    try std.testing.expectEqualStrings("-end", r.buf);
}

test "CBOR skip parsing" {
    inline for (.{
        "\x00",
        "\x40",
        "\x41a",
        "\x5f\xff",
        "\x5f\x41a\xff",
        "\x80",
        "\x81\x00",
        "\x9f\xff",
        "\x9f\x9f\xff\xff",
        "\x9f\x9f\x81\x00\xff\xff",
        "\xa0",
        "\xa1\x00\x01",
        "\xbf\xff",
        "\xbf\xc0\x00\x9f\xff\xff",
    }) |s| {
        var r = CborReader{.buf = s ++ "garbage"};
        try (try r.next()).skip();
        try std.testing.expectEqualStrings(r.buf, "garbage");
    }
}

const ItemParser = struct {
    r: CborReader,
    len: ?usize = null,

    const Field = struct {
        key: ItemKey,
        val: CborVal,
    };

    fn init(buf: []const u8) !ItemParser {
        var r = ItemParser{.r = .{.buf = buf}};
        const head = try r.r.next();
        if (head.major != .map) return error.Invalid;
        if (!head.indef) r.len = head.arg;
        return r;
    }

    fn key(r: *ItemParser) !?CborVal {
        if (r.len) |*l| {
            if (l.* == 0) return null;
            l.* -= 1;
            return try r.r.next();
        } else {
            const v = try r.r.next();
            return if (v.end()) null else v;
        }
    }

    // Skips over any fields that don't fit into an ItemKey.
    fn next(r: *ItemParser) !?Field {
        while (try r.key()) |k| {
            if (k.int(@typeInfo(ItemKey).Enum.tag_type)) |n| return .{
                .key = @enumFromInt(n),
                .val = try r.r.next(),
            } else |_| {
                try k.skip();
                try (try r.r.next()).skip();
            }
        }
        return null;
    }
};

// Returned buffer is valid until the next readItem().
fn readItem(ref: u64) ItemParser {
    if (ref >= (1 << (24 + 32))) die("invalid itemref {x}", .{ref});
    const block = readBlock(@intCast(ref >> 24));
    if ((ref & 0xffffff) > block.len) die("itemref {x} exceeds block size", .{ref});
    return ItemParser.init(block[(ref & 0xffffff)..]) catch die("invalid item at ref {x}", .{ref});
}

const Import = struct {
    sink: *sink.Thread,
    stat: sink.Stat = .{},
    fields: Fields = .{},
    p: ItemParser = undefined,

    const Fields = struct {
        name: []const u8 = "",
        rderr: bool = false,
        prev: ?u64 = null,
        sub: ?u64 = null,
    };

    fn readFields(ctx: *Import, ref: u64) !void {
        ctx.p = readItem(ref);
        var hastype = false;

        while (try ctx.p.next()) |kv| switch (kv.key) {
            .type => {
                ctx.stat.etype = try kv.val.etype();
                hastype = true;
            },
            .name => ctx.fields.name = try kv.val.bytes(),
            .prev => ctx.fields.prev = try kv.val.itemref(ref),
            .asize => ctx.stat.size = try kv.val.int(u64),
            .dsize => ctx.stat.blocks = @intCast(try kv.val.int(u64)/512),
            .dev => ctx.stat.dev = try kv.val.int(u64),
            .rderr => ctx.fields.rderr = kv.val.major == .simple and kv.val.arg == 21,
            .sub => ctx.fields.sub = try kv.val.itemref(ref),
            .ino => ctx.stat.ino = try kv.val.int(u64),
            .nlink => ctx.stat.nlink = try kv.val.int(u31),
            .uid => ctx.stat.ext.uid = try kv.val.int(u32),
            .gid => ctx.stat.ext.gid = try kv.val.int(u32),
            .mode => ctx.stat.ext.mode = try kv.val.int(u16),
            .mtime => ctx.stat.ext.mtime = try kv.val.int(u64),
            else => try kv.val.skip(),
        };

        if (!hastype) return error.MissingType;
        if (ctx.fields.name.len == 0) return error.MissingName;
    }

    fn import(ctx: *Import, ref: u64, parent: ?*sink.Dir, dev: u64) void {
        ctx.stat = .{ .dev = dev };
        ctx.fields = .{};
        ctx.readFields(ref) catch |e| die("item {x}: {}", .{ref, e});

        if (ctx.stat.etype == .dir) {
            const prev = ctx.fields.prev;
            const dir =
                if (parent) |d| d.addDir(ctx.sink, ctx.fields.name, &ctx.stat)
                else sink.createRoot(ctx.fields.name, &ctx.stat);
            ctx.sink.setDir(dir);
            if (ctx.fields.rderr) dir.setReadError(ctx.sink);

            ctx.fields.prev = ctx.fields.sub;
            while (ctx.fields.prev) |n| ctx.import(n, dir, ctx.stat.dev);

            ctx.sink.setDir(parent);
            dir.unref(ctx.sink);
            ctx.fields.prev = prev;

        } else {
            const p = parent orelse die("root item must be a directory", .{});
            if (@intFromEnum(ctx.stat.etype) < 0)
                p.addSpecial(ctx.sink, ctx.fields.name, ctx.stat.etype)
            else
                p.addStat(ctx.sink, ctx.fields.name, &ctx.stat);
        }

        if ((ctx.sink.files_seen.load(.monotonic) & 65) == 0)
            main.handleEvent(false, false);
    }
};

// Walk through the directory tree in depth-first order and pass results to sink.zig.
// Depth-first is required for JSON export, but more efficient strategies are
// possible for other sinks. Parallel import is also an option, but that's more
// complex and likely less efficient than a streaming import.
pub fn import() void {
    const sink_threads = sink.createThreads(1);
    var ctx = Import{.sink = &sink_threads[0]};
    ctx.import(bigu64(global.index[global.index.len-8..][0..8].*), null, 0);
    sink.done();
}

// Assumes that the file signature has already been read and validated.
pub fn open(fd: std.fs.File) !void {
    global.fd = fd;

    const size = try fd.getEndPos();
    if (size < 16) return error.EndOfStream;

    // Read index block
    var buf: [4]u8 = undefined;
    if (try fd.preadAll(&buf, size - 4) != 4) return error.EndOfStream;
    const index_header = bigu32(buf);
    if ((index_header >> 24) != 2 or (index_header & 7) != 0)
        die("invalid index block ({x})", .{index_header});
    const len = (index_header & 0x00ffffff) - 8; // excluding block header & footer
    if (len >= size) die("invalid index block size", .{});
    global.index = main.allocator.alloc(u8, len) catch unreachable;
    if (try fd.preadAll(global.index, size - len - 4) != global.index.len) return error.EndOfStream;
}
