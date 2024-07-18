// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const mem_src = @import("mem_src.zig");
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


// JSON output is necessarily single-threaded and items MUST be added depth-first.
const JsonWriter = struct {
    fd: std.fs.File,
    // Must be large enough to hold PATH_MAX*6 plus some overhead.
    // (The 6 is because, in the worst case, every byte expands to a "\u####"
    // escape, and we do pessimistic estimates here in order to avoid checking
    // buffer lengths for each and every write operation)
    buf: [64*1024]u8 = undefined,
    off: usize = 0,
    dir_entry_open: bool = false,

    fn flush(ctx: *JsonWriter, bytes: usize) void {
        @setCold(true);
        // This can only really happen when the root path exceeds PATH_MAX,
        // in which case we would probably have error'ed out earlier anyway.
        if (bytes > ctx.buf.len) ui.die("Error writing JSON export: path too long.\n", .{});
        ctx.fd.writeAll(ctx.buf[0..ctx.off]) catch |e|
            ui.die("Error writing to file: {s}.\n", .{ ui.errorString(e) });
        ctx.off = 0;
    }

    fn ensureSpace(ctx: *JsonWriter, bytes: usize) void {
        if (bytes > ctx.buf.len - ctx.off) ctx.flush(bytes);
    }

    fn write(ctx: *JsonWriter, s: []const u8) void {
        @memcpy(ctx.buf[ctx.off..][0..s.len], s);
        ctx.off += s.len;
    }

    fn writeByte(ctx: *JsonWriter, b: u8) void {
        ctx.buf[ctx.off] = b;
        ctx.off += 1;
    }

    // Write escaped string contents, excluding the quotes.
    fn writeStr(ctx: *JsonWriter, s: []const u8) void {
        for (s) |b| {
            if (b >= 0x20 and b != '"' and b != '\\' and b != 127) ctx.writeByte(b)
            else switch (b) {
                '\n' => ctx.write("\\n"),
                '\r' => ctx.write("\\r"),
                0x8  => ctx.write("\\b"),
                '\t' => ctx.write("\\t"),
                0xC  => ctx.write("\\f"),
                '\\' => ctx.write("\\\\"),
                '"'  => ctx.write("\\\""),
                else => {
                    ctx.write("\\u00");
                    const hexdig = "0123456789abcdef";
                    ctx.writeByte(hexdig[b>>4]);
                    ctx.writeByte(hexdig[b&0xf]);
                },
            }
        }
    }

    fn writeUint(ctx: *JsonWriter, n: u64) void {
        // Based on std.fmt.formatInt
        var a = n;
        var buf: [24]u8 = undefined;
        var index: usize = buf.len;
        while (a >= 100) : (a = @divTrunc(a, 100)) {
            index -= 2;
            buf[index..][0..2].* = std.fmt.digits2(@as(usize, @intCast(a % 100)));
        }
        if (a < 10) {
            index -= 1;
            buf[index] = '0' + @as(u8, @intCast(a));
        } else {
            index -= 2;
            buf[index..][0..2].* = std.fmt.digits2(@as(usize, @intCast(a)));
        }
        ctx.write(buf[index..]);
    }

    fn init(out: std.fs.File) *JsonWriter {
        var ctx = main.allocator.create(JsonWriter) catch unreachable;
        ctx.* = .{ .fd = out };
        ctx.write("[1,2,{\"progname\":\"ncdu\",\"progver\":\"" ++ main.program_version ++ "\",\"timestamp\":");
        ctx.writeUint(@intCast(@max(0, std.time.timestamp())));
        ctx.writeByte('}');
        return ctx;
    }

    // A newly written directory entry is left "open", i.e. the '}' to close
    // the item object is not written, to allow for a setReadError() to be
    // caught if one happens before the first sub entry.
    // Any read errors after the first sub entry are thrown away, but that's
    // just a limitation of the JSON format.
    fn closeDirEntry(ctx: *JsonWriter, rderr: bool) void {
        if (ctx.dir_entry_open) {
            ctx.dir_entry_open = false;
            if (rderr) ctx.write(",\"read_error\":true");
            ctx.writeByte('}');
        }
    }

    fn addSpecial(ctx: *JsonWriter, name: []const u8, t: Special) void {
        ctx.closeDirEntry(false);
        ctx.ensureSpace(name.len*6 + 1000);
        // not necessarily correct, but mimics model.Entry.isDirectory()
        const isdir = switch (t) {
            .other_fs, .kernfs => true,
            .err, .excluded => false,
        };
        ctx.write(if (isdir) ",\n[{\"name\":\"" else ",\n{\"name\":\"");
        ctx.writeStr(name);
        ctx.writeStr(switch (t) {
            .err => "\",\"read_error\":true",
            .other_fs => "\",\"excluded\":\"othfs\"",
            .kernfs => "\",\"excluded\":\"kernfs\"",
            .excluded => "\",\"excluded\":\"pattern\"",
        });
        if (isdir) ctx.writeByte(']');
    }

    fn writeStat(ctx: *JsonWriter, name: []const u8, stat: *const Stat, parent_dev: u64) void {
        ctx.ensureSpace(name.len*6 + 1000);
        ctx.write(if (stat.dir) ",\n[{\"name\":\"" else ",\n{\"name\":\"");
        ctx.writeStr(name);
        ctx.writeByte('"');
        if (stat.size > 0) {
            ctx.write(",\"asize\":");
            ctx.writeUint(stat.size);
        }
        if (stat.blocks > 0) {
            ctx.write(",\"dsize\":");
            ctx.writeUint(util.blocksToSize(stat.blocks));
        }
        if (stat.dir and stat.dev != parent_dev) {
            ctx.write(",\"dev\":");
            ctx.writeUint(stat.dev);
        }
        if (stat.hlinkc) {
            ctx.write(",\"ino\":");
            ctx.writeUint(stat.ino);
            ctx.write(",\"hlnkc\":true,\"nlink\":");
            ctx.writeUint(stat.nlink);
        }
        if (!stat.dir and !stat.reg) ctx.write(",\"notreg\":true");
        if (main.config.extended) {
            ctx.write(",\"uid\":");
            ctx.writeUint(stat.ext.uid);
            ctx.write(",\"gid\":");
            ctx.writeUint(stat.ext.gid);
            ctx.write(",\"mode\":");
            ctx.writeUint(stat.ext.mode);
            ctx.write(",\"mtime\":");
            ctx.writeUint(stat.ext.mtime);
        }
    }

    fn addStat(ctx: *JsonWriter, name: []const u8, stat: *const Stat) void {
        ctx.closeDirEntry(false);
        ctx.writeStat(name, stat, undefined);
        ctx.writeByte('}');
    }

    fn addDir(ctx: *JsonWriter, name: []const u8, stat: *const Stat, parent_dev: u64) void {
        ctx.closeDirEntry(false);
        ctx.writeStat(name, stat, parent_dev);
        ctx.dir_entry_open = true;
    }

    fn setReadError(ctx: *JsonWriter) void {
        ctx.closeDirEntry(true);
    }

    fn close(ctx: *JsonWriter) void {
        ctx.ensureSpace(1000);
        ctx.closeDirEntry(false);
        ctx.writeByte(']');
    }

    fn done(ctx: *JsonWriter) void {
        ctx.write("]\n");
        ctx.flush(0);
        ctx.fd.close();
        main.allocator.destroy(ctx);
    }
};


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
        if (t == .err) self.dir.pack.suberr = true;

        const e = self.getEntry(alloc, .file, false, name);
        e.file().?.pack = switch (t) {
            .err => .{ .err = true },
            .other_fs => .{ .other_fs = true },
            .kernfs => .{ .kernfs = true },
            .excluded => .{ .excluded = true },
        };
    }

    fn addStat(self: *MemDir, alloc: std.mem.Allocator, name: []const u8, stat: *const Stat) *model.Entry {
        if (state.defer_json == null) {
            self.dir.items +|= 1;
            if (!stat.hlinkc) {
                self.dir.entry.pack.blocks +|= stat.blocks;
                self.dir.entry.size +|= stat.size;
            }
            if (self.dir.entry.ext()) |e| {
                if (stat.ext.mtime > e.mtime) e.mtime = stat.ext.mtime;
            }
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
        if (e.link()) |l| {
            l.parent = self.dir;
            l.ino = stat.ino;
            l.pack.nlink = stat.nlink;
            model.inodes.lock.lock();
            defer model.inodes.lock.unlock();
            l.addLink();
        }
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
                if (self.entries.getKey(e) == e) it.* = e.next
                else it = &e.next;
            }
        }
        self.entries.deinit();

        if (state.defer_json != null) return;

        // Grab counts collected from subdirectories
        self.dir.entry.pack.blocks +|= self.blocks;
        self.dir.entry.size +|= self.bytes;
        self.dir.items +|= self.items;
        if (self.suberr) self.dir.pack.suberr = true;
        if (self.dir.entry.ext()) |e| {
            if (self.mtime > e.mtime) e.mtime = self.mtime;
        }

        // Add own counts to parent
        if (parent) |p| {
            p.lock.lock();
            defer p.lock.unlock();
            p.blocks +|= self.dir.entry.pack.blocks - self.own_blocks;
            p.bytes +|= self.dir.entry.size - self.own_bytes;
            p.items +|= self.dir.items;
            if (self.dir.entry.ext()) |e| {
                if (e.mtime > p.mtime) p.mtime = e.mtime;
            }
            if (self.suberr or self.dir.pack.suberr or self.dir.pack.err) p.suberr = true;
        }
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
        json: struct {
            dev: u64,
            wr: *JsonWriter,
        },
    };

    pub fn addSpecial(d: *Dir, t: *Thread, name: []const u8, sp: Special) void {
        _ = t.files_seen.fetchAdd(1, .monotonic);
        switch (d.out) {
            .mem => |*m| m.addSpecial(t.arena.allocator(), name, sp),
            .json => |j| j.wr.addSpecial(name, sp),
        }
        if (sp == .err) {
            state.last_error_lock.lock();
            defer state.last_error_lock.unlock();
            if (state.last_error) |p| main.allocator.free(p);
            const p = d.path();
            state.last_error = std.fs.path.joinZ(main.allocator, &.{ p, name }) catch unreachable;
            main.allocator.free(p);
        }
    }

    pub fn addStat(d: *Dir, t: *Thread, name: []const u8, stat: *const Stat) void {
        _ = t.files_seen.fetchAdd(1, .monotonic);
        _ = t.bytes_seen.fetchAdd((stat.blocks *| 512) / @max(1, stat.nlink), .monotonic);
        std.debug.assert(!stat.dir);
        switch (d.out) {
            .mem => |*m| _ = m.addStat(t.arena.allocator(), name, stat),
            .json => |j| j.wr.addStat(name, stat),
        }
    }

    pub fn addDir(d: *Dir, t: *Thread, name: []const u8, stat: *const Stat) *Dir {
        _ = t.files_seen.fetchAdd(1, .monotonic);
        _ = t.bytes_seen.fetchAdd(stat.blocks *| 512, .monotonic);
        std.debug.assert(stat.dir);

        const s = main.allocator.create(Dir) catch unreachable;
        s.* = .{
            .name = main.allocator.dupe(u8, name) catch unreachable,
            .parent = d,
            .out = switch (d.out) {
                .mem => |*m| .{
                    .mem = MemDir.init(m.addStat(t.arena.allocator(), name, stat).dir().?)
                },
                .json => |j| blk: {
                    std.debug.assert(d.refcnt.load(.monotonic) == 1);
                    j.wr.addDir(name, stat, j.dev);
                    break :blk .{ .json = .{ .wr = j.wr, .dev = stat.dev } };
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
            .json => |j| j.wr.setReadError(),
        }
        state.last_error_lock.lock();
        defer state.last_error_lock.unlock();
        if (state.last_error) |p| main.allocator.free(p);
        state.last_error = d.path();
    }

    fn path(d: *Dir) [:0]u8 {
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
        return out.toOwnedSliceSentinel(0) catch unreachable;
    }

    fn ref(d: *Dir) void {
        _ = d.refcnt.fetchAdd(1, .monotonic);
    }

    pub fn unref(d: *Dir) void {
        if (d.refcnt.fetchSub(1, .release) != 1) return;
        d.refcnt.fence(.acquire);

        switch (d.out) {
            .mem => |*m| m.final(if (d.parent) |p| &p.out.mem else null),
            .json => |j| j.wr.close(),
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
    pub var status: enum { done, err, zeroing, hlcnt, running } = .running;
    pub var threads: []Thread = undefined;
    pub var out: Out = .{ .mem = null };
    pub var defer_json: ?*JsonWriter = null;

    pub var last_error: ?[:0]u8 = null;
    var last_error_lock = std.Thread.Mutex{};
    var need_confirm_quit = false;

    pub const Out = union(enum) {
        mem: ?*model.Dir,
        json: *JsonWriter,
    };
};


pub fn setupJsonOutput(out: std.fs.File) void {
    state.out = state.Out{ .json = JsonWriter.init(out) };
}


// Must be the first thing to call from a source; initializes global state.
pub fn createThreads(num: usize) []Thread {
    switch (state.out) {
        .mem => {},
        .json => |j| {
            if (num > 1) {
                state.out = state.Out{ .mem = null };
                state.defer_json = j;
            }
        },
    }

    state.status = .running;
    if (state.last_error) |p| main.allocator.free(p);
    state.last_error = null;
    state.threads = main.allocator.alloc(Thread, num) catch unreachable;
    for (state.threads) |*t| t.* = .{};
    return state.threads;
}


// Must be the last thing to call from a source.
pub fn done() void {
    switch (state.out) {
        .mem => if (state.defer_json == null) {
            state.status = .hlcnt;
            main.handleEvent(false, true);
            const dir = state.out.mem orelse model.root;
            var it: ?*model.Dir = dir;
            while (it) |p| : (it = p.parent) {
                p.updateSubErr();
                if (p != dir) {
                    p.entry.pack.blocks +|= dir.entry.pack.blocks;
                    p.entry.size +|= dir.entry.size;
                    p.items +|= dir.items + 1;
                }
            }
            model.inodes.addAllStats();
        },
        .json => |j| j.done(),
    }
    state.status = .done;
    main.allocator.free(state.threads);

    // We scanned into memory, now we need to scan from memory to JSON
    if (state.defer_json) |j| {
        state.out = state.Out{ .json = j };
        state.defer_json = null;
        mem_src.run(model.root);
    }

    // Clear the screen when done.
    if (main.config.scan_ui == .line) main.handleEvent(false, true);
}


pub fn createRoot(path: []const u8, stat: *const Stat) *Dir {
    const out = switch (state.out) {
        .mem => |parent| sw: {
            const p = parent orelse blk: {
                model.root = model.Entry.create(main.allocator, .dir, main.config.extended, path).dir().?;
                break :blk model.root;
            };
            state.status = .zeroing;
            if (p.items > 10_000) main.handleEvent(false, true);
            // Do the zeroStats() here, after the "root" entry has been
            // stat'ed and opened, so that a fatal error on refresh won't
            // zero-out the requested directory.
            p.entry.zeroStats(p.parent);
            state.status = .running;
            p.entry.pack.blocks = stat.blocks;
            p.entry.size = stat.size;
            p.pack.dev = model.devices.getId(stat.dev);
            break :sw Dir.Out{ .mem = MemDir.init(p) };
        },
        .json => |ctx| sw: {
            ctx.addDir(path, stat, 0);
            break :sw Dir.Out{ .json = .{ .wr = ctx, .dev = stat.dev } };
        },
    };

    const d = main.allocator.create(Dir) catch unreachable;
    d.* = .{
        .name = main.allocator.dupe(u8, path) catch unreachable,
        .parent = null,
        .out = out,
    };
    return d;
}


fn drawConsole() void {
    const st = struct {
        var ansi: ?bool = null;
        var lines_written: usize = 0;
    };
    const stderr = std.io.getStdErr();
    const ansi = st.ansi orelse blk: {
        const t = stderr.supportsAnsiEscapeCodes();
        st.ansi = t;
        break :blk t;
    };

    var buf: [4096]u8 = undefined;
    var strm = std.io.fixedBufferStream(buf[0..]);
    var wr = strm.writer();
    while (ansi and st.lines_written > 0) {
        wr.writeAll("\x1b[1F\x1b[2K") catch {};
        st.lines_written -= 1;
    }

    if (state.status == .hlcnt) {
        wr.writeAll("Counting hardlinks...\n") catch {};

    } else if (state.status == .running) {
        var bytes: u64 = 0;
        var files: u64 = 0;
        for (state.threads) |*t| {
            bytes +|= t.bytes_seen.load(.monotonic);
            files += t.files_seen.load(.monotonic);
        }
        const r = ui.FmtSize.fmt(bytes);
        wr.print("{} files / {s}{s}\n", .{files, r.num(), r.unit}) catch {};
        st.lines_written += 1;

        for (state.threads, 0..) |*t, i| {
            const dir = blk: {
                t.lock.lock();
                defer t.lock.unlock();
                break :blk if (t.current_dir) |d| d.path() else null;
            };
            wr.print("  #{}: {s}\n", .{i+1, ui.shorten(ui.toUtf8(dir orelse "(waiting)"), 73)}) catch {};
            st.lines_written += 1;
            if (dir) |p| main.allocator.free(p);
        }
    }

    stderr.writeAll(strm.getWritten()) catch {};
}


fn drawProgress() void {
    const st = struct { var animation_pos: usize = 0; };

    var bytes: u64 = 0;
    var files: u64 = 0;
    for (state.threads) |*t| {
        bytes +|= t.bytes_seen.load(.monotonic);
        files += t.files_seen.load(.monotonic);
    }

    ui.init();
    const width = ui.cols -| 5;
    const numthreads: u32 = @intCast(@min(state.threads.len, @max(1, ui.rows -| 10)));
    const box = ui.Box.create(8 + numthreads, width, "Scanning...");
    box.move(2, 2);
    ui.addstr("Total items: ");
    ui.addnum(.default, files);

    if (width > 48) {
        box.move(2, 30);
        ui.addstr("size: ");
        ui.addsize(.default, bytes);
    }

    for (0..numthreads) |i| {
        box.move(3+@as(u32, @intCast(i)), 4);
        const dir = blk: {
            const t = &state.threads[i];
            t.lock.lock();
            defer t.lock.unlock();
            break :blk if (t.current_dir) |d| d.path() else null;
        };
        ui.addstr(ui.shorten(ui.toUtf8(dir orelse "(waiting)"), width -| 6));
        if (dir) |p| main.allocator.free(p);
    }

    blk: {
        state.last_error_lock.lock();
        defer state.last_error_lock.unlock();
        const err = state.last_error orelse break :blk;
        box.move(4 + numthreads, 2);
        ui.style(.bold);
        ui.addstr("Warning: ");
        ui.style(.default);
        ui.addstr("error scanning ");
        ui.addstr(ui.shorten(ui.toUtf8(err), width -| 28));
        box.move(5 + numthreads, 3);
        ui.addstr("some directory sizes may not be correct.");
    }

    if (state.need_confirm_quit) {
        box.move(6 + numthreads, width -| 20);
        ui.addstr("Press ");
        ui.style(.key);
        ui.addch('y');
        ui.style(.default);
        ui.addstr(" to confirm");
    } else {
        box.move(6 + numthreads, width -| 18);
        ui.addstr("Press ");
        ui.style(.key);
        ui.addch('q');
        ui.style(.default);
        ui.addstr(" to abort");
    }

    if (main.config.update_delay < std.time.ns_per_s and width > 40) {
        const txt = "Scanning...";
        st.animation_pos += 1;
        if (st.animation_pos >= txt.len*2) st.animation_pos = 0;
        if (st.animation_pos < txt.len) {
            box.move(6 + numthreads, 2);
            for (txt[0..st.animation_pos + 1]) |t| ui.addch(t);
        } else {
            var i: u32 = txt.len-1;
            while (i > st.animation_pos-txt.len) : (i -= 1) {
                box.move(6 + numthreads, 2+i);
                ui.addch(txt[i]);
            }
        }
    }
}


fn drawError() void {
    const width = ui.cols -| 5;
    const box = ui.Box.create(6, width, "Scan error");

    box.move(2, 2);
    ui.addstr("Unable to open directory:");
    box.move(3, 4);
    ui.addstr(ui.shorten(ui.toUtf8(state.last_error.?), width -| 10));

    box.move(4, width -| 27);
    ui.addstr("Press any key to continue");
}


fn drawMessage(msg: []const u8) void {
    const width = ui.cols -| 5;
    const box = ui.Box.create(4, width, "Scan error");
    box.move(2, 2);
    ui.addstr(msg);
}


pub fn draw() void {
    switch (main.config.scan_ui.?) {
        .none => {},
        .line => drawConsole(),
        .full => switch (state.status) {
            .done => {},
            .err => drawError(),
            .zeroing => {
                const box = ui.Box.create(4, ui.cols -| 5, "Initializing");
                box.move(2, 2);
                ui.addstr("Clearing directory counts...");
            },
            .hlcnt => {
                const box = ui.Box.create(4, ui.cols -| 5, "Finalizing");
                box.move(2, 2);
                ui.addstr("Counting hardlinks...");
            },
            .running => drawProgress(),
        },
    }
}


pub fn keyInput(ch: i32) void {
    switch (state.status) {
        .done => {},
        .err => main.state = .browse,
        .zeroing => {},
        .hlcnt => {},
        .running => {
            switch (ch) {
                'q' => {
                    if (main.config.confirm_quit) state.need_confirm_quit = !state.need_confirm_quit
                   else ui.quit();
                },
                'y', 'Y' => if (state.need_confirm_quit) ui.quit(),
                else => state.need_confirm_quit = false,
            }
        },
    }
}
