// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const sink = @import("sink.zig");
const util = @import("util.zig");
const ui = @import("ui.zig");

pub const global = struct {
    var fd: std.fs.File = undefined;
    var index = std.ArrayList(u8).init(main.allocator);
    var file_off: u64 = 0;
    var lock: std.Thread.Mutex = .{};
    var root_itemref: u64 = 0;
    // TODO:
    // var links: Map dev -> ino -> (last_offset, size, blocks, nlink)
};

const BLOCK_SIZE: usize = 64*1024;

const ItemType = enum(i3) {
    dir = 0,
    reg = 1,
    nonreg = 2,
    link = 3,
    err = -1,
    pattern = -2,
    otherfs = -3,
    kernfs = -4
};

const ItemKey = enum(u5) {
    // all items
    type = 0, // ItemType
    name = 1, // bytes
    prev = 2, // itemref
    // Only for non-specials
    asize = 3, // u64
    dsize = 4, // u64
    // Only for .dir
    dev      =  5, // u64        only if different from parent dir
    rderr    =  6, // bool       true = error reading directory list, false = error in sub-item, absent = no error
    cumasize =  7, // u64
    cumdsize =  8, // u64
    shrasize =  9, // u64
    shrdsize = 10, // u64
    items    = 11, // u32
    sub      = 12, // itemref    only if dir is not empty
    // Only for .link
    ino     = 13, // u64
    nlink   = 14, // u32
    prevlnk = 15, // itemref
    // Extended mode
    uid   = 16, // u32
    gid   = 17, // u32
    mode  = 18, // u16
    mtime = 19, // u64
};

// Pessimistic upper bound on the encoded size of an item, excluding the name field.
// 2 bytes for map start/end, 10 per field (2 for the key, 9 for a full u64).
const MAX_ITEM_LEN = 2 + 11 * @typeInfo(ItemKey).Enum.fields.len;

const CborMajor = enum(u3) { pos, neg, bytes, text, array, map, tag, simple };

inline fn bigu16(v: u16) [2]u8 { return @bitCast(std.mem.nativeToBig(u16, v)); }
inline fn bigu32(v: u32) [4]u8 { return @bitCast(std.mem.nativeToBig(u32, v)); }
inline fn bigu64(v: u64) [8]u8 { return @bitCast(std.mem.nativeToBig(u64, v)); }

inline fn blockHeader(id: u8, len: u32) [4]u8 { return bigu32((@as(u32, id) << 24) | len); }

inline fn cborByte(major: CborMajor, arg: u5) u8 { return (@as(u8, @intFromEnum(major)) << 5) | arg; }


pub const Thread = struct {
    buf: [BLOCK_SIZE]u8 = undefined,
    off: usize = BLOCK_SIZE,
    block_num: u32 = std.math.maxInt(u32),
    itemref: u64 = 0, // ref of item currently being written

    // Temporary buffer for headers and compression
    tmp: [BLOCK_SIZE+128]u8 = undefined,

    fn createBlock(t: *Thread) []const u8 {
        if (t.block_num == std.math.maxInt(u32) or t.off <= 1) return "";

        // TODO: Compression
        const blocklen: u32 = @intCast(t.off + 16);
        t.tmp[0..4].* = blockHeader(1, blocklen);
        t.tmp[4..8].* = bigu32(t.block_num);
        t.tmp[8..12].* = bigu32(@intCast(t.off));
        @memcpy(t.tmp[12..][0..t.off], t.buf[0..t.off]);
        t.tmp[12+t.off..][0..4].* = blockHeader(1, blocklen);
        return t.tmp[0..blocklen];
    }

    fn flush(t: *Thread, expected_len: usize) void {
        @setCold(true);
        const block = createBlock(t);

        global.lock.lock();
        defer global.lock.unlock();
        // This can only really happen when the root path exceeds BLOCK_SIZE,
        // in which case we would probably have error'ed out earlier anyway.
        if (expected_len > t.buf.len) ui.die("Error writing data: path too long.\n", .{});

        if (block.len > 0) {
            global.index.items[4..][t.block_num*8..][0..8].* = bigu64((global.file_off << 24) + block.len);
            global.file_off += block.len;
            global.fd.writeAll(block) catch |e|
                ui.die("Error writing to file: {s}.\n", .{ ui.errorString(e) });
        }

        t.off = 0;
        t.block_num = @intCast((global.index.items.len - 4) / 8);
        global.index.appendSlice(&[1]u8{0}**8) catch unreachable;
        // Start the first block with a CBOR 'null', so that itemrefs can never be 0.
        if (t.block_num == 0) t.cborHead(.simple, 22);
    }

    fn cborHead(t: *Thread, major: CborMajor, arg: u64) void {
        if (arg <= 23) {
            t.buf[t.off] = cborByte(major, @intCast(arg));
            t.off += 1;
        } else if (arg <= std.math.maxInt(u8)) {
            t.buf[t.off] = cborByte(major, 24);
            t.buf[t.off+1] = @truncate(arg);
            t.off += 2;
        } else if (arg <= std.math.maxInt(u16)) {
            t.buf[t.off] = cborByte(major, 25);
            t.buf[t.off+1..][0..2].* = bigu16(@intCast(arg));
            t.off += 3;
        } else if (arg <= std.math.maxInt(u32)) {
            t.buf[t.off] = cborByte(major, 26);
            t.buf[t.off+1..][0..4].* = bigu32(@intCast(arg));
            t.off += 5;
        } else {
            t.buf[t.off] = cborByte(major, 27);
            t.buf[t.off+1..][0..8].* = bigu64(arg);
            t.off += 9;
        }
    }

    fn cborIndef(t: *Thread, major: CborMajor) void {
        t.buf[t.off] = cborByte(major, 31);
        t.off += 1;
    }

    fn itemKey(t: *Thread, key: ItemKey) void {
        t.cborHead(.pos, @intFromEnum(key));
    }

    fn itemRef(t: *Thread, key: ItemKey, ref: u64) void {
        if (ref == 0) return;
        t.itemKey(key);
        // Full references compress like shit and most of the references point
        // into the same block, so optimize that case by using a negative
        // offset instead.
        if ((ref >> 24) == t.block_num) t.cborHead(.neg, t.itemref - ref - 1)
        else t.cborHead(.pos, ref);
    }

    // Reserve space for a new item, write out the type, prev and name fields and return the itemref.
    fn itemStart(t: *Thread, itype: ItemType, prev_item: u64, name: []const u8) u64 {
        const min_len = name.len + MAX_ITEM_LEN;
        if (t.off + min_len > t.buf.len) t.flush(min_len);

        t.itemref = (@as(u64, t.block_num) << 24) | t.off;
        t.cborIndef(.map);
        t.itemKey(.type);
        if (@intFromEnum(itype) >= 0) t.cborHead(.pos, @intCast(@intFromEnum(itype)))
        else t.cborHead(.neg, @intCast(-1 - @intFromEnum(itype)));
        t.itemKey(.name);
        t.cborHead(.bytes, name.len);
        @memcpy(t.buf[t.off..][0..name.len], name);
        t.off += name.len;
        t.itemRef(.prev, prev_item);
        return t.itemref;
    }

    fn itemExt(t: *Thread, stat: *const sink.Stat) void {
        if (!main.config.extended) return;
        t.itemKey(.uid);
        t.cborHead(.pos, stat.ext.uid);
        t.itemKey(.gid);
        t.cborHead(.pos, stat.ext.gid);
        t.itemKey(.mode);
        t.cborHead(.pos, stat.ext.mode);
        t.itemKey(.mtime);
        t.cborHead(.pos, stat.ext.mtime);
    }

    fn itemEnd(t: *Thread) void {
        t.cborIndef(.simple);
    }
};


pub const Dir = struct {
    // TODO: When items are written out into blocks depth-first, parent dirs
    // will end up getting their items distributed over many blocks, which will
    // significantly slow down reading that dir's listing. It may be worth
    // buffering some items at the Dir level before flushing them out to the
    // Thread buffer.

    // The lock protects all of the below, and is necessary because final()
    // accesses the parent dir and may be called from other threads.
    // I'm not expecting much lock contention, but it's possible to turn
    // last_item into an atomic integer and other fields could be split up for
    // subdir use.
    lock: std.Thread.Mutex = .{},
    last_sub: u64 = 0,
    stat: sink.Stat,
    items: u32 = 0,
    size: u64 = 0,
    blocks: u64 = 0,
    err: bool = false,
    suberr: bool = false,
    // TODO: set of links
    //shared_size: u64,
    //shared_blocks: u64,

    pub fn addSpecial(d: *Dir, t: *Thread, name: []const u8, sp: sink.Special) void {
        d.lock.lock();
        defer d.lock.unlock();
        d.items += 1;
        if (sp == .err) d.suberr = true;
        const it: ItemType = switch (sp) {
            .err => .err,
            .other_fs => .otherfs,
            .kernfs => .kernfs,
            .excluded => .pattern,
        };
        d.last_sub = t.itemStart(it, d.last_sub, name);
        t.itemEnd();
    }

    pub fn addStat(d: *Dir, t: *Thread, name: []const u8, stat: *const sink.Stat) void {
        d.lock.lock();
        defer d.lock.unlock();
        d.items += 1;
        if (!stat.hlinkc) {
            d.size +|= stat.size;
            d.blocks +|= stat.blocks;
        }
        const it: ItemType = if (stat.hlinkc) .link else if (stat.reg) .reg else .nonreg;
        d.last_sub = t.itemStart(it, d.last_sub, name);
        t.itemKey(.asize);
        t.cborHead(.pos, stat.size);
        t.itemKey(.dsize);
        t.cborHead(.pos, util.blocksToSize(stat.blocks));
        // TODO: hardlink stuff
        t.itemExt(stat);
        t.itemEnd();
    }

    pub fn addDir(d: *Dir, stat: *const sink.Stat) Dir {
        d.lock.lock();
        defer d.lock.unlock();
        d.items += 1;
        d.size +|= stat.size;
        d.blocks +|= stat.blocks;
        return .{ .stat = stat.* };
    }

    pub fn setReadError(d: *Dir) void {
        d.lock.lock();
        defer d.lock.unlock();
        d.err = true;
    }

    pub fn final(d: *Dir, t: *Thread, name: []const u8, parent: ?*Dir) void {
        if (parent) |p| p.lock.lock();
        defer if (parent) |p| p.lock.unlock();

        // TODO: hardlink stuff
        if (parent) |p| {
            p.items += d.items;
            p.size +|= d.size;
            p.blocks +|= d.blocks;
            if (d.suberr or d.err) p.suberr = true;

            p.last_sub = t.itemStart(.dir, p.last_sub, name);
        } else
            global.root_itemref = t.itemStart(.dir, 0, name);

        t.itemKey(.asize);
        t.cborHead(.pos, d.stat.size);
        t.itemKey(.dsize);
        t.cborHead(.pos, util.blocksToSize(d.stat.blocks));
        if (parent == null or parent.?.stat.dev != d.stat.dev) {
            t.itemKey(.dev);
            t.cborHead(.pos, d.stat.dev);
        }
        if (d.err or d.suberr) {
            t.itemKey(.rderr);
            t.cborHead(.simple, if (d.err) 21 else 20);
        }
        t.itemKey(.cumasize);
        t.cborHead(.pos, d.size);
        t.itemKey(.cumdsize);
        t.cborHead(.pos, util.blocksToSize(d.blocks));
        t.itemKey(.items);
        t.cborHead(.pos, d.items);
        t.itemRef(.sub, d.last_sub);
        t.itemExt(&d.stat);
        t.itemEnd();
    }
};


pub fn createRoot(stat: *const sink.Stat) Dir {
    return .{ .stat = stat.* };
}

pub fn done(threads: []sink.Thread) void {
    for (threads) |*t| t.sink.bin.flush(0);

    while (std.mem.endsWith(u8, global.index.items, &[1]u8{0}**8))
        global.index.shrinkRetainingCapacity(global.index.items.len - 8);
    global.index.appendSlice(&bigu64(global.root_itemref)) catch unreachable;
    global.index.appendSlice(&blockHeader(2, @intCast(global.index.items.len + 4))) catch unreachable;
    global.index.items[0..4].* = blockHeader(2, @intCast(global.index.items.len));
    global.fd.writeAll(global.index.items) catch |e|
        ui.die("Error writing to file: {s}.\n", .{ ui.errorString(e) });
    global.index.clearAndFree();

    global.fd.close();
}

pub fn setupOutput(fd: std.fs.File) void {
    global.fd = fd;
    fd.writeAll("\xbfncduEX1") catch |e|
        ui.die("Error writing to file: {s}.\n", .{ ui.errorString(e) });
    global.file_off = 8;

    // Placeholder for the index block header.
    global.index.appendSlice("aaaa") catch unreachable;
}
