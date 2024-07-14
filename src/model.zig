// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const ui = @import("ui.zig");
const util = @import("util.zig");

pub const EType = enum(u2) { dir, link, file };

// Type for the Entry.Packed.blocks field. Smaller than a u64 to make room for flags.
pub const Blocks = u61;

// Memory layout:
//      (Ext +) Dir + name
//  or: (Ext +) Link + name
//  or: (Ext +) File + name
//
// Entry is always the first part of Dir, Link and File, so a pointer cast to
// *Entry is always safe and an *Entry can be casted to the full type. The Ext
// struct, if present, is placed before the *Entry pointer.
// These are all packed structs and hence do not have any alignment, which is
// great for saving memory but perhaps not very great for code size or
// performance.
pub const Entry = extern struct {
    pack: Packed align(1),
    size: u64 align(1) = 0,
    next: ?*Entry align(1) = null,

    pub const Packed = packed struct(u64) {
        etype: EType,
        isext: bool,
        blocks: Blocks = 0, // 512-byte blocks
    };

    const Self = @This();

    pub fn dir(self: *Self) ?*Dir {
        return if (self.pack.etype == .dir) @ptrCast(self) else null;
    }

    pub fn link(self: *Self) ?*Link {
        return if (self.pack.etype == .link) @ptrCast(self) else null;
    }

    pub fn file(self: *Self) ?*File {
        return if (self.pack.etype == .file) @ptrCast(self) else null;
    }

    // Whether this entry should be displayed as a "directory".
    // Some dirs are actually represented in this data model as a File for efficiency.
    pub fn isDirectory(self: *Self) bool {
        return if (self.file()) |f| f.pack.other_fs or f.pack.kernfs else self.pack.etype == .dir;
    }

    pub fn name(self: *const Self) [:0]const u8 {
        const self_name = switch (self.pack.etype) {
            .dir => &@as(*const Dir, @ptrCast(self)).name,
            .link => &@as(*const Link, @ptrCast(self)).name,
            .file => &@as(*const File, @ptrCast(self)).name,
        };
        const name_ptr: [*:0]const u8 = @ptrCast(self_name);
        return std.mem.sliceTo(name_ptr, 0);
    }

    pub fn ext(self: *Self) ?*Ext {
        if (!self.pack.isext) return null;
        return @ptrCast(@as([*]Ext, @ptrCast(self)) - 1);
    }

    fn alloc(comptime T: type, allocator: std.mem.Allocator, etype: EType, isext: bool, ename: []const u8) *Entry {
        const size = (if (isext) @as(usize, @sizeOf(Ext)) else 0) + @sizeOf(T) + ename.len + 1;
        var ptr = blk: while (true) {
            if (allocator.allocWithOptions(u8, size, 1, null)) |p| break :blk p
            else |_| {}
            ui.oom();
        };
        if (isext) {
            @as(*Ext, @ptrCast(ptr)).* = .{};
            ptr = ptr[@sizeOf(Ext)..];
        }
        const e: *T = @ptrCast(ptr);
        e.* = .{ .entry = .{ .pack = .{ .etype = etype, .isext = isext } } };
        const n = @as([*]u8, @ptrCast(&e.name))[0..ename.len+1];
        @memcpy(n[0..ename.len], ename);
        n[ename.len] = 0;
        return &e.entry;
    }

    pub fn create(allocator: std.mem.Allocator, etype: EType, isext: bool, ename: []const u8) *Entry {
        return switch (etype) {
            .dir  => alloc(Dir, allocator, etype, isext, ename),
            .file => alloc(File, allocator, etype, isext, ename),
            .link => alloc(Link, allocator, etype, isext, ename),
        };
    }

    fn hasErr(self: *Self) bool {
        return
            if (self.file()) |f| f.pack.err
            else if (self.dir()) |d| d.pack.err or d.pack.suberr
            else false;
    }

    fn zeroStatsRec(self: *Entry) void {
        self.pack.blocks = 0;
        self.size = 0;
        if (self.file()) |f| f.pack = .{};
        if (self.dir()) |d| {
            d.items = 0;
            d.pack.err = false;
            d.pack.suberr = false;
            var it = d.sub;
            while (it) |e| : (it = e.next) zeroStatsRec(e);
        }
    }

    // Recursively set stats and those of sub-items to zero and removes counts
    // from parent directories; as if this item does not exist in the tree.
    // XXX: Does not update the 'suberr' flag of parent directories, make sure
    // to call updateSubErr() afterwards.
    pub fn zeroStats(self: *Entry, parent: ?*Dir) void {
        // TODO: Uncount nested links.

        var it = parent;
        while (it) |p| : (it = p.parent) {
            p.entry.pack.blocks -|= self.pack.blocks;
            p.entry.size -|= self.size;
            p.items -|= 1 + (if (self.dir()) |d| d.items else 0);
        }
        self.zeroStatsRec();
    }
};

const DevId = u30; // Can be reduced to make room for more flags in Dir.Packed.

pub const Dir = extern struct {
    entry: Entry,

    sub: ?*Entry align(1) = null,
    parent: ?*Dir align(1) = null,

    // entry.{blocks,size}: Total size of all unique files + dirs. Non-shared hardlinks are counted only once.
    //   (i.e. the space you'll need if you created a filesystem with only this dir)
    // shared_*: Unique hardlinks that still have references outside of this directory.
    //   (i.e. the space you won't reclaim by deleting this dir)
    // (space reclaimed by deleting a dir =~ entry. - shared_)
    shared_blocks: u64 align(1) = 0,
    shared_size: u64 align(1) = 0,
    items: u32 align(1) = 0,

    pack: Packed align(1) = .{},

    // Only used to find the @offsetOff, the name is written at this point as a 0-terminated string.
    // (Old C habits die hard)
    name: [0]u8 = undefined,

    pub const Packed = packed struct {
        // Indexes into the global 'devices.list' array
        dev: DevId = 0,
        err: bool = false,
        suberr: bool = false,
    };

    pub fn fmtPath(self: *const @This(), withRoot: bool, out: *std.ArrayList(u8)) void {
        if (!withRoot and self.parent == null) return;
        var components = std.ArrayList([:0]const u8).init(main.allocator);
        defer components.deinit();
        var it: ?*const @This() = self;
        while (it) |e| : (it = e.parent)
            if (withRoot or e.parent != null)
                components.append(e.entry.name()) catch unreachable;

        var i: usize = components.items.len-1;
        while (true) {
            if (i != components.items.len-1 and !(out.items.len != 0 and out.items[out.items.len-1] == '/')) out.append('/') catch unreachable;
            out.appendSlice(components.items[i]) catch unreachable;
            if (i == 0) break;
            i -= 1;
        }
    }

    // Only updates the suberr of this Dir, assumes child dirs have already
    // been updated and does not propagate to parents.
    pub fn updateSubErr(self: *@This()) void {
        self.pack.suberr = false;
        var sub = self.sub;
        while (sub) |e| : (sub = e.next) {
            if (e.hasErr()) {
                self.pack.suberr = true;
                break;
            }
        }
    }
};

// File that's been hardlinked (i.e. nlink > 1)
pub const Link = extern struct {
    entry: Entry,
    parent: *Dir align(1) = undefined,
    next: *Link align(1) = undefined, // Singly circular linked list of all *Link nodes with the same dev,ino.
    // dev is inherited from the parent Dir
    ino: u64 align(1) = undefined,
    name: [0]u8 = undefined,

    // Return value should be freed with main.allocator.
    pub fn path(self: *const @This(), withRoot: bool) [:0]const u8 {
        var out = std.ArrayList(u8).init(main.allocator);
        self.parent.fmtPath(withRoot, &out);
        out.append('/') catch unreachable;
        out.appendSlice(self.entry.name()) catch unreachable;
        return out.toOwnedSliceSentinel(0) catch unreachable;
    }
};

// Anything that's not an (indexed) directory or hardlink. Excluded directories are also "Files".
pub const File = extern struct {
    entry: Entry,
    pack: Packed = .{},
    name: [0]u8 = undefined,

    pub const Packed = packed struct(u8) {
        err: bool = false,
        excluded: bool = false,
        other_fs: bool = false,
        kernfs: bool = false,
        notreg: bool = false,
        _pad: u3 = 0, // Make this struct "ABI sized" to allow inclusion in an extern struct
    };
};

pub const Ext = extern struct {
    mtime: u64 align(1) = 0,
    uid: u32 align(1) = 0,
    gid: u32 align(1) = 0,
    mode: u16 align(1) = 0,
};


// List of st_dev entries. Those are typically 64bits, but that's quite a waste
// of space when a typical scan won't cover many unique devices.
pub const devices = struct {
    var lock = std.Thread.Mutex{};
    // id -> dev
    pub var list = std.ArrayList(u64).init(main.allocator);
    // dev -> id
    var lookup = std.AutoHashMap(u64, DevId).init(main.allocator);

    pub fn getId(dev: u64) DevId {
        lock.lock();
        defer lock.unlock();
        const d = lookup.getOrPut(dev) catch unreachable;
        if (!d.found_existing) {
            d.value_ptr.* = @as(DevId, @intCast(list.items.len));
            list.append(dev) catch unreachable;
        }
        return d.value_ptr.*;
    }
};


// Lookup table for ino -> *Link entries, used for hard link counting.
pub const inodes = struct {
    // Keys are hashed by their (dev,ino), the *Link points to an arbitrary
    // node in the list. Link entries with the same dev/ino are part of a
    // circular linked list, so you can iterate through all of them with this
    // single pointer.
    const Map = std.HashMap(*Link, Inode, HashContext, 80);
    pub var map = Map.init(main.allocator);

    // List of nodes in 'map' with !counted, to speed up addAllStats().
    // If this list grows large relative to the number of nodes in 'map', then
    // this list is cleared and uncounted_full is set instead, so that
    // addAllStats() will do a full iteration over 'map'.
    var uncounted = std.HashMap(*Link, void, HashContext, 80).init(main.allocator);
    var uncounted_full = true; // start with true for the initial scan

    const Inode = packed struct {
        // Whether this Inode is counted towards the parent directories.
        counted: bool,
        // Number of links for this inode. When set to '0', we don't know the
        // actual nlink count, either because it wasn't part of the imported
        // JSON data or because we read inconsistent values from the
        // filesystem.  The count will then be updated by the actual number of
        // links in our in-memory tree.
        nlink: u31,
    };

    const HashContext = struct {
        pub fn hash(_: @This(), l: *Link) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(std.mem.asBytes(&@as(u32, l.parent.pack.dev)));
            h.update(std.mem.asBytes(&l.ino));
            return h.final();
        }

        pub fn eql(_: @This(), a: *Link, b: *Link) bool {
            return a.ino == b.ino and a.parent.pack.dev == b.parent.pack.dev;
        }
    };

    fn addUncounted(l: *Link) void {
        if (uncounted_full) return;
        if (uncounted.count() > map.count()/8) {
            uncounted.clearAndFree();
            uncounted_full = true;
        } else
            (uncounted.getOrPut(l) catch unreachable).key_ptr.* = l;
    }

    // Add/remove this inode from the parent Dir sizes. When removing stats,
    // the list of *Links and their sizes and counts must be in the exact same
    // state as when the stats were added. Hence, any modification to the Link
    // state should be preceded by a setStats(.., false).
    fn setStats(entry: Map.Entry, add: bool) void {
        if (entry.value_ptr.counted == add) return;
        entry.value_ptr.counted = add;

        var nlink: u31 = 0;
        var dirs = std.AutoHashMap(*Dir, u32).init(main.allocator);
        defer dirs.deinit();
        var it = entry.key_ptr.*;
        while (true) {
            nlink += 1;
            var parent: ?*Dir = it.parent;
            while (parent) |p| : (parent = p.parent) {
                const de = dirs.getOrPut(p) catch unreachable;
                if (de.found_existing) de.value_ptr.* += 1
                else de.value_ptr.* = 1;
            }
            it = it.next;
            if (it == entry.key_ptr.*)
                break;
        }

        if (entry.value_ptr.nlink < nlink) entry.value_ptr.nlink = nlink
        else nlink = entry.value_ptr.nlink;

        var dir_iter = dirs.iterator();
        if (add) {
            while (dir_iter.next()) |de| {
                de.key_ptr.*.entry.pack.blocks +|= entry.key_ptr.*.entry.pack.blocks;
                de.key_ptr.*.entry.size        +|= entry.key_ptr.*.entry.size;
                if (de.value_ptr.* < nlink) {
                    de.key_ptr.*.shared_blocks +|= entry.key_ptr.*.entry.pack.blocks;
                    de.key_ptr.*.shared_size   +|= entry.key_ptr.*.entry.size;
                }
            }
        } else {
            while (dir_iter.next()) |de| {
                de.key_ptr.*.entry.pack.blocks -|= entry.key_ptr.*.entry.pack.blocks;
                de.key_ptr.*.entry.size        -|= entry.key_ptr.*.entry.size;
                if (de.value_ptr.* < nlink) {
                    de.key_ptr.*.shared_blocks -|= entry.key_ptr.*.entry.pack.blocks;
                    de.key_ptr.*.shared_size   -|= entry.key_ptr.*.entry.size;
                }
            }
        }
    }

    pub fn addAllStats() void {
        if (uncounted_full) {
            var it = map.iterator();
            while (it.next()) |e| setStats(e, true);
        } else {
            var it = uncounted.iterator();
            while (it.next()) |u| if (map.getEntry(u.key_ptr.*)) |e| setStats(e, true);
        }
        uncounted_full = false;
        if (uncounted.count() > 0)
            uncounted.clearAndFree();
    }
};


pub var root: *Dir = undefined;


test "entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var e = Entry.create(arena.allocator(), .file, false, "hello");
    try std.testing.expectEqual(e.pack.etype, .file);
    try std.testing.expect(!e.pack.isext);
    try std.testing.expectEqualStrings(e.name(), "hello");
}
