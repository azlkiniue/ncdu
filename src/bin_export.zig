// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const sink = @import("sink.zig");
const util = @import("util.zig");
const ui = @import("ui.zig");
const c = @cImport({
    @cInclude("zlib.h");
    @cInclude("zstd.h");
    @cInclude("lz4.h");
});

pub const global = struct {
    var fd: std.fs.File = undefined;
    var index = std.ArrayList(u8).init(main.allocator);
    var file_off: u64 = 0;
    var lock: std.Thread.Mutex = .{};
    var root_itemref: u64 = 0;
};

const BLOCK_SIZE: usize = 512*1024; // XXX: Current maximum for benchmarking, should just stick with a fixed block size.

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
    // Extended mode
    uid   = 15, // u32
    gid   = 16, // u32
    mode  = 17, // u16
    mtime = 18, // u64
};

// Pessimistic upper bound on the encoded size of an item, excluding the name field.
// 2 bytes for map start/end, 11 per field (2 for the key, 9 for a full u64).
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

    // Temporary buffer for headers and compression.
    // TODO: check with compressBound()/ZSTD_compressBound()
    tmp: [BLOCK_SIZE+128]u8 = undefined,

    fn compressNone(in: []const u8, out: []u8) usize {
        @memcpy(out[0..in.len], in);
        return in.len;
    }

    fn compressZlib(in: []const u8, out: []u8) usize {
        var outlen: c.uLongf = out.len;
        const r = c.compress2(out.ptr, &outlen, in.ptr, in.len, main.config.complevel);
        std.debug.assert(r == c.Z_OK);
        return outlen;
    }

    fn compressZstd(in: []const u8, out: []u8) usize {
        const r = c.ZSTD_compress(out.ptr, out.len, in.ptr, in.len, main.config.complevel);
        std.debug.assert(c.ZSTD_isError(r) == 0);
        return r;
    }

    fn compressLZ4(in: []const u8, out: []u8) usize {
        const r = c.LZ4_compress_default(in.ptr, out.ptr, @intCast(in.len), @intCast(out.len));
        std.debug.assert(r > 0);
        return @intCast(r);
    }

    fn createBlock(t: *Thread) []const u8 {
        if (t.block_num == std.math.maxInt(u32) or t.off <= 1) return "";

        const bodylen = switch (main.config.compression) {
            .none => compressNone(t.buf[0..t.off], t.tmp[12..]),
            .zlib => compressZlib(t.buf[0..t.off], t.tmp[12..]),
            .zstd => compressZstd(t.buf[0..t.off], t.tmp[12..]),
            .lz4 => compressLZ4(t.buf[0..t.off], t.tmp[12..]),
        };
        const blocklen: u32 = @intCast(bodylen + 16);
        t.tmp[0..4].* = blockHeader(1, blocklen);
        t.tmp[4..8].* = bigu32(t.block_num);
        t.tmp[8..12].* = bigu32(@intCast(t.off));
        t.tmp[12+bodylen..][0..4].* = blockHeader(1, blocklen);
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
        if (t.off + min_len > main.config.blocksize) t.flush(min_len);

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
    shared_size: u64 = 0,
    shared_blocks: u64 = 0,
    inodes: Inodes = Inodes.init(main.allocator),

    const Inodes = std.AutoHashMap(u64, Inode);
    const Inode = struct {
        size: u64,
        blocks: u64,
        nlink: u32,
        nfound: u32,
    };


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

        if (stat.hlinkc) {
            const lnk = d.inodes.getOrPut(stat.ino) catch unreachable;
            if (!lnk.found_existing) lnk.value_ptr.* = .{
                .size = stat.size,
                .blocks = stat.blocks,
                .nlink = stat.nlink,
                .nfound = 1,
            } else lnk.value_ptr.nfound += 1;
            t.itemKey(.ino);
            t.cborHead(.pos, stat.ino);
            t.itemKey(.nlink);
            t.cborHead(.pos, stat.nlink);
        }

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

    // XXX: older JSON exports did not include the nlink count and have
    // this field set to '0'.  We can deal with that when importing to
    // mem_sink, but the hardlink counting algorithm used here really does need
    // that information. Current code makes sure to count such links only once
    // per dir, but does not count them towards the shared_* fields. That
    // behavior is similar to ncdu 1.x, but the difference between memory
    // import and this file export might be surprising.
    fn countLinks(d: *Dir, parent: ?*Dir) void {
        var parent_new: u32 = 0;
        var it = d.inodes.iterator();
        while (it.next()) |kv| {
            const v = kv.value_ptr;
            d.size +|= v.size;
            d.blocks +|= v.blocks;
            if (v.nlink > 1 and v.nfound <= v.nlink) {
                d.shared_size +|= v.size;
                d.shared_blocks +|= v.blocks;
            }

            const p = parent orelse continue;
            // All contained in this dir, no need to keep this entry around
            if (v.nlink > 0 and v.nfound >= v.nlink) {
                p.size +|= v.size;
                p.blocks +|= v.blocks;
                _ = d.inodes.remove(kv.key_ptr.*);
            } else if (!p.inodes.contains(kv.key_ptr.*))
                parent_new += 1;
        }

        // Merge remaining inodes into parent
        const p = parent orelse return;
        if (d.inodes.count() == 0) return;

        // If parent is empty, just transfer
        if (p.inodes.count() == 0) {
            p.inodes.deinit();
            p.inodes = d.inodes;
            d.inodes = Inodes.init(main.allocator); // So we can deinit() without affecting parent
        // Otherwise, merge
        } else {
            p.inodes.ensureUnusedCapacity(parent_new) catch unreachable;
            it = d.inodes.iterator();
            while (it.next()) |kv| {
                const v = kv.value_ptr;
                const plnk = p.inodes.getOrPutAssumeCapacity(kv.key_ptr.*);
                if (!plnk.found_existing) plnk.value_ptr.* = v.*
                else plnk.value_ptr.*.nfound += v.nfound;
            }
        }
    }

    pub fn final(d: *Dir, t: *Thread, name: []const u8, parent: ?*Dir) void {
        if (parent) |p| p.lock.lock();
        defer if (parent) |p| p.lock.unlock();

        if (parent) |p| {
            // Different dev? Don't merge the 'inodes' sets, just count the
            // links here first so the sizes get added to the parent.
            if (p.stat.dev != d.stat.dev) d.countLinks(null);

            p.items += d.items;
            p.size +|= d.size;
            p.blocks +|= d.blocks;
            if (d.suberr or d.err) p.suberr = true;

            // Same dir, merge inodes
            if (p.stat.dev == d.stat.dev) d.countLinks(p);

            p.last_sub = t.itemStart(.dir, p.last_sub, name);
        } else {
            d.countLinks(null);
            global.root_itemref = t.itemStart(.dir, 0, name);
        }
        d.inodes.deinit();

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
        t.cborHead(.pos, d.size +| d.stat.size);
        t.itemKey(.cumdsize);
        t.cborHead(.pos, util.blocksToSize(d.blocks +| d.stat.blocks));
        if (d.shared_size > 0) {
            t.itemKey(.shrasize);
            t.cborHead(.pos, d.shared_size);
        }
        if (d.shared_blocks > 0) {
            t.itemKey(.shrdsize);
            t.cborHead(.pos, util.blocksToSize(d.shared_blocks));
        }
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
