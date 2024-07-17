// SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const sink = @import("sink.zig");

// Emit the memory tree to the sink in depth-first order from a single thread,
// suitable for JSON export.

fn toStat(e: *model.Entry) sink.Stat {
    const el = e.link();
    return sink.Stat{
        .blocks = e.pack.blocks,
        .size = e.size,
        .dev =
            if (e.dir()) |d| model.devices.list.items[d.pack.dev]
            else if (el) |l| model.devices.list.items[l.parent.pack.dev]
            else undefined,
        .ino = if (el) |l| l.ino else undefined,
        .nlink = if (el) |l| l.pack.nlink else undefined,
        .hlinkc = el != null,
        .dir = e.pack.etype == .dir,
        .reg = if (e.file()) |f| !f.pack.notreg else e.pack.etype != .dir,
        .symlink = undefined,
        .ext = if (e.ext()) |x| x.* else .{},
    };
}

const Ctx = struct {
    sink: *sink.Thread,
    stat: sink.Stat,
};


fn rec(ctx: *Ctx, dir: *sink.Dir, entry: *model.Entry) void {
    if ((ctx.sink.files_seen.load(.monotonic) & 1024) == 0)
        main.handleEvent(false, false);

    ctx.stat = toStat(entry);
    if (entry.dir()) |d| {
        var ndir = dir.addDir(ctx.sink, entry.name(), &ctx.stat);
        ctx.sink.setDir(ndir);
        if (d.pack.err) ndir.setReadError(ctx.sink);
        var it = d.sub;
        while (it) |e| : (it = e.next) rec(ctx, ndir, e);
        ctx.sink.setDir(dir);
        ndir.unref();
        return;
    }
    if (entry.file()) |f| {
        if (f.pack.err) return dir.addSpecial(ctx.sink, entry.name(), .err);
        if (f.pack.excluded) return dir.addSpecial(ctx.sink, entry.name(), .excluded);
        if (f.pack.other_fs) return dir.addSpecial(ctx.sink, entry.name(), .other_fs);
        if (f.pack.kernfs) return dir.addSpecial(ctx.sink, entry.name(), .kernfs);
    }
    dir.addStat(ctx.sink, entry.name(), &ctx.stat);
}


pub fn run(d: *model.Dir) void {
    const sink_threads = sink.createThreads(1);

    var ctx = .{
        .sink = &sink_threads[0],
        .stat = toStat(&d.entry),
    };
    var buf = std.ArrayList(u8).init(main.allocator);
    d.fmtPath(true, &buf);
    const root = sink.createRoot(buf.items, &ctx.stat);
    buf.deinit();

    var it = d.sub;
    while (it) |e| : (it = e.next) rec(&ctx, root, e);

    root.unref();
    sink.done();
}
