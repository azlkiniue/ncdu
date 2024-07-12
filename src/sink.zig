// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const ui = @import("ui.zig");
const util = @import("util.zig");

// "sink" in this case is where the scan/import results (from scan.zig and
// json_import.zig) are being forwarded to and processed. This code handles
// aggregating the tree structure into memory or exporting it as JSON. Also
// handles progress display.

// API for sources:
//
// Single-threaded:
//
//   dir = createRoot(name, stat)
//   dir.addSpecial(name, opt)
//   dir.addFile(name, stat)
//   sub = dir.addDir(name, stat)
//     (no dir.stuff here)
//     sub.addstuff();
//     sub.unref();
//   dir.unref();
//
// Multi-threaded interleaving:
//
//   dir = createRoot(name, stat)
//   dir.addSpecial(name, opt)
//   dir.addFile(name, stat)
//   sub = dir.addDir(...)
//     sub.addstuff();
//   sub2 = dir.addDir(..);
//     sub.unref();
//   dir.unref(); // <- no more direct descendants for x, but subdirs could still be active
//     sub2.addStuff();
//     sub2.unref(); // <- this is where 'dir' is really done.
//
// Rule:
//   No concurrent method calls on a single Dir object, but objects may be passed between threads.


// Concise stat struct for fields we're interested in, with the types used by the model.
pub const Stat = struct {
    blocks: model.Blocks = 0,
    size: u64 = 0,
    dev: u64 = 0,
    ino: u64 = 0,
    nlink: u31 = 0,
    hlinkc: bool = false,
    dir: bool = false,
    reg: bool = true,
    symlink: bool = false,
    ext: model.Ext = .{},
};

pub const Special = enum { err, other_fs, kernfs, excluded };


const MemDir = struct {
    dir: *model.Dir,
    entries: Map,

    own_blocks: model.Blocks,
    own_bytes: u64,

    // Additional counts collected from subdirectories. Subdirs may run final()
    // from separate threads so these need to be protected.
    blocks: model.Blocks = 0,
    bytes: u64 = 0,
    items: u32 = 0,
    mtime: u64 = 0,
    suberr: bool = false,
    lock: std.Thread.Mutex = .{},

    const Map = std.HashMap(*model.Entry, void, HashContext, 80);

    const HashContext = struct {
        pub fn hash(_: @This(), e: *model.Entry) u64 {
            return std.hash.Wyhash.hash(0, e.name());
        }
        pub fn eql(_: @This(), a: *model.Entry, b: *model.Entry) bool {
            return a == b or std.mem.eql(u8, a.name(), b.name());
        }
    };

    const HashContextAdapted = struct {
        pub fn hash(_: @This(), v: []const u8) u64 {
            return std.hash.Wyhash.hash(0, v);
        }
        pub fn eql(_: @This(), a: []const u8, b: *model.Entry) bool {
            return std.mem.eql(u8, a, b.name());
        }
    };

    fn init(dir: *model.Dir) MemDir {
        var self = MemDir{
            .dir = dir,
            .entries = Map.initContext(main.allocator, HashContext{}),
            .own_blocks = dir.entry.pack.blocks,
            .own_bytes = dir.entry.size,
        };

        var count: Map.Size = 0;
        var it = dir.sub;
        while (it) |e| : (it = e.next) count += 1;
        self.entries.ensureUnusedCapacity(count) catch unreachable;

        it = dir.sub;
        while (it) |e| : (it = e.next)
            self.entries.putAssumeCapacity(e, {});
        return self;
    }

    fn getEntry(self: *MemDir, alloc: std.mem.Allocator, etype: model.EType, isext: bool, name: []const u8) *model.Entry {
        if (self.entries.getKeyAdapted(name, HashContextAdapted{})) |e| {
            // XXX: In-place conversion may be possible in some cases.
            if (e.pack.etype == etype and (!isext or e.pack.isext)) {
                e.pack.isext = isext;
                _ = self.entries.removeAdapted(name, HashContextAdapted{});
                return e;
            }
        }
        const e = model.Entry.create(alloc, etype, isext, name);
        e.next = self.dir.sub;
        self.dir.sub = e;
        return e;
    }

    fn addSpecial(self: *MemDir, alloc: std.mem.Allocator, name: []const u8, t: Special) void {
        self.dir.items += 1;

        const e = self.getEntry(alloc, .file, false, name);
        e.file().?.pack = switch (t) {
            .err => .{ .err = true },
            .other_fs => .{ .other_fs = true },
            .kernfs => .{ .kernfs = true },
            .excluded => .{ .excluded = true },
        };
    }

    fn addStat(self: *MemDir, alloc: std.mem.Allocator, name: []const u8, stat: *const Stat) *model.Entry {
        self.dir.items +|= 1;
        if (!stat.hlinkc) {
            self.dir.entry.pack.blocks +|= stat.blocks;
            self.dir.entry.size +|= stat.size;
        }

        const etype = if (stat.dir) model.EType.dir
                      else if (stat.hlinkc) model.EType.link
                      else model.EType.file;
        const e = self.getEntry(alloc, etype, main.config.extended, name);
        e.pack.blocks = stat.blocks;
        e.size = stat.size;
        if (e.dir()) |d| {
            d.parent = self.dir;
            d.pack.dev = model.devices.getId(stat.dev);
        }
        if (e.file()) |f| f.pack = .{ .notreg = !stat.dir and !stat.reg };
        if (e.link()) |l| l.ino = stat.ino; // TODO: Add to inodes table
        if (e.ext()) |ext| ext.* = stat.ext;
        return e;
    }

    fn setReadError(self: *MemDir) void {
        self.dir.pack.err = true;
    }

    fn final(self: *MemDir, parent: ?*MemDir) void {
        // Remove entries we've not seen
        if (self.entries.count() > 0) {
            var it = &self.dir.sub;
            while (it.*) |e| {
                if (self.entries.contains(e)) it.* = e.next
                else it = &e.next;
            }
        }

        // Grab counts collected from subdirectories
        self.dir.entry.pack.blocks +|= self.blocks;
        self.dir.entry.size +|= self.bytes;
        self.dir.items +|= self.items;
        if (self.suberr) self.dir.pack.suberr = true;
        if (self.dir.entry.ext()) |e| {
            if (self.mtime > e.mtime) self.mtime = e.mtime;
        }

        // Add own counts to parent
        if (parent) |p| {
            p.lock.lock();
            defer p.lock.unlock();
            p.blocks +|= self.dir.entry.pack.blocks - self.own_blocks;
            p.bytes +|= self.dir.entry.size - self.own_bytes;
            p.items +|= self.dir.items;
            if (self.dir.entry.ext()) |e| {
                if (e.mtime > p.mtime) e.mtime = p.mtime;
            }
            if (self.suberr or self.dir.pack.err) p.suberr = true;
        }
        self.entries.deinit();
    }
};


pub const Dir = struct {
    refcnt: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),
    // (XXX: This allocation can be avoided when scanning to a MemDir)
    name: []const u8,
    parent: ?*Dir,
    out: Out,

    const Out = union(enum) {
        mem: MemDir,
    };

    pub fn addSpecial(d: *Dir, t: *Thread, name: []const u8, sp: Special) void {
        _ = t.files_seen.fetchAdd(1, .monotonic);
        switch (d.out) {
            .mem => |*m| m.addSpecial(t.arena.allocator(), name, sp),
        }
    }

    pub fn addStat(d: *Dir, t: *Thread, name: []const u8, stat: *const Stat) void {
        _ = t.files_seen.fetchAdd(1, .monotonic);
        _ = t.bytes_seen.fetchAdd((stat.blocks *| 512) / @max(1, stat.nlink), .monotonic);
        switch (d.out) {
            .mem => |*m| _ = m.addStat(t.arena.allocator(), name, stat),
        }
    }

    pub fn addDir(d: *Dir, t: *Thread, name: []const u8, stat: *const Stat) *Dir {
        _ = t.files_seen.fetchAdd(1, .monotonic);
        _ = t.bytes_seen.fetchAdd(stat.blocks *| 512, .monotonic);

        const s = main.allocator.create(Dir) catch unreachable;
        s.* = .{
            .name = main.allocator.dupe(u8, name) catch unreachable,
            .parent = d,
            .out = switch (d.out) {
                .mem => |*m| .{
                    .mem = MemDir.init(m.addStat(t.arena.allocator(), name, stat).dir().?)
                },
            },
        };
        d.ref();
        return s;
    }

    pub fn setReadError(d: *Dir, t: *Thread) void {
        _ = t;
        switch (d.out) {
            .mem => |*m| m.setReadError(),
        }
    }

    fn path(d: *Dir) []const u8 {
        var components = std.ArrayList([]const u8).init(main.allocator);
        defer components.deinit();
        var it: ?*Dir = d;
        while (it) |e| : (it = e.parent) components.append(e.name) catch unreachable;

        var out = std.ArrayList(u8).init(main.allocator);
        var i: usize = components.items.len-1;
        while (true) {
            if (i != components.items.len-1 and !(out.items.len != 0 and out.items[out.items.len-1] == '/')) out.append('/') catch unreachable;
            out.appendSlice(components.items[i]) catch unreachable;
            if (i == 0) break;
            i -= 1;
        }
        return out.toOwnedSlice() catch unreachable;
    }

    fn ref(d: *Dir) void {
        _ = d.refcnt.fetchAdd(1, .monotonic);
    }

    pub fn unref(d: *Dir) void {
        if (d.refcnt.fetchSub(1, .release) != 1) return;
        d.refcnt.fence(.acquire);

        switch (d.out) {
            .mem => |*m| m.final(if (d.parent) |p| &p.out.mem else null),
        }

        if (d.parent) |p| p.unref();
        if (d.name.len > 0) main.allocator.free(d.name);
        main.allocator.destroy(d);
    }
};


pub const Thread = struct {
    current_dir: ?*Dir = null,
    lock: std.Thread.Mutex = .{},
    bytes_seen: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    files_seen: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    // Arena allocator for model.Entry structs, these are never freed.
    arena: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(std.heap.page_allocator),

    pub fn setDir(t: *Thread, d: ?*Dir) void {
        t.lock.lock();
        defer t.lock.unlock();
        t.current_dir = d;
    }
};


pub const state = struct {
    pub var threads: []Thread = undefined;
};


pub fn createRoot(path: []const u8, stat: *const Stat) *Dir {
    // TODO: Handle other outputs
    model.root = model.Entry.create(main.allocator, .dir, main.config.extended, path).dir().?;
    model.root.entry.pack.blocks = stat.blocks;
    model.root.entry.size = stat.size;
    model.root.pack.dev = model.devices.getId(stat.dev);

    const d = main.allocator.create(Dir) catch unreachable;
    d.* = .{
        .name = main.allocator.dupe(u8, path) catch unreachable,
        .parent = null,
        .out = .{ .mem = MemDir.init(model.root) },
    };
    return d;
}


pub fn draw() void {
    var bytes: u64 = 0;
    var files: u64 = 0;
    for (state.threads) |*t| {
        bytes +|= t.bytes_seen.load(.monotonic);
        files += t.files_seen.load(.monotonic);
    }
    const r = ui.FmtSize.fmt(bytes);
    std.debug.print("{} files / {s}{s}\n", .{files, r.num(), r.unit});

    for (state.threads, 0..) |*t, i| {
        const dir = blk: {
            t.lock.lock();
            defer t.lock.unlock();
            break :blk if (t.current_dir) |d| d.path() else null;
        };
        std.debug.print("  #{}: {s}\n", .{i, dir orelse "(waiting)"});
        if (dir) |p| main.allocator.free(p);
    }
}

pub fn keyInput(_: i32) void {
}
