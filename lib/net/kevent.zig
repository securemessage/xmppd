//! Hardened kevent(2) wrapper over std.c.kevent.
//!
//! Zig 0.15.2 `std.posix.kevent` maps EBADF and EINVAL to `unreachable`
//! (std/posix.zig:4595-4597); a daemon must see both as errors, so this module
//! calls the libc symbol directly and decodes every errno into an explicit
//! set. No path maps an errno to unreachable.
//!
//! Kernel semantics relied on (kern_kevent, /usr/src/sys/kern/kern_event.c):
//! every change in the changelist is attempted; a failing change is written
//! into the eventlist as an EV_ERROR record (errno in `data`, the change's
//! own `udata` preserved) while eventlist room remains. When at least one
//! change failed, kevent returns those records without scanning for ready
//! events. Only `nevents == 0` fails the whole call on a bad change, so
//! submitWait callers must always pass room for at least `changes.len`
//! records. EINTR retries with an empty changelist: the kernel applies all
//! changes before it sleeps, so re-submitting them would double-apply deletes.

const std = @import("std");
const posix = std.posix;

pub const Kevent = std.c.Kevent;

pub const SubmitWaitError = error{
    KqueueInvalid, // EBADF: kq closed or not a kqueue
    InvalidArgument, // EINVAL: bad timeout or count
    ChangeRejected, // kernel had no room for failure records (caller bug)
    SystemResources, // ENOMEM
    Unexpected, // errno_out carries the raw errno
};

/// Apply `changes` and harvest up to `events.len` ready events in one syscall.
/// Returns the number of harvested events (failure records included). EINTR
/// retries automatically; the changelist is not re-submitted after an EINTR
/// (it was already applied). `errno_out` carries the raw errno on
/// error.Unexpected.
pub fn submitWait(
    kq: posix.fd_t,
    changes: []const Kevent,
    events: []Kevent,
    timeout: ?*const posix.timespec,
    errno_out: *u32,
) SubmitWaitError!usize {
    std.debug.assert(events.len >= changes.len);
    var pending: []const Kevent = changes;
    while (true) {
        const rc = std.c.kevent(
            kq,
            pending.ptr,
            @intCast(pending.len),
            events.ptr,
            @intCast(events.len),
            timeout,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => {
                // Changes were applied before the scan was interrupted.
                pending = &.{};
                continue;
            },
            .BADF => return error.KqueueInvalid,
            .INVAL => return error.InvalidArgument,
            .NOMEM => return error.SystemResources,
            .ACCES, .NOENT, .SRCH, .FAULT => {
                // With a non-empty eventlist these only surface as EV_ERROR
                // records; seeing them here means the kernel had no room.
                return error.ChangeRejected;
            },
            else => {
                errno_out.* = @intFromEnum(posix.errno(rc));
                return error.Unexpected;
            },
        }
    }
}

pub const ApplyError = error{
    NotFound, // ENOENT: no such knote (EV_DELETE)
    BadDescriptor, // EBADF on the target fd (EVFILT_READ/WRITE)
    InvalidArgument,
    ProcessNotFound, // ESRCH: EVFILT_PROC on a dead or foreign pid
    AccessDenied, // EACCES
    SystemResources, // ENOMEM or the kernel knote limit
    KqueueInvalid, // EBADF on kq
    Unexpected,
};

/// One immediate change with an empty eventlist, for registrations that must
/// take effect before the next wait (signal watch, process watch, EV_DELETE on
/// detach, EVFILT_USER trigger). Whole-call errors map one-to-one to ApplyError
/// and `errno_out`, when given, always carries the raw errno on failure.
pub fn applyNow(kq: posix.fd_t, change: *const Kevent, errno_out: ?*u32) ApplyError!void {
    var none: [0]Kevent = undefined;
    while (true) {
        const one = [1]Kevent{change.*};
        const rc = std.c.kevent(kq, &one, 1, &none, 0, null);
        const e = posix.errno(rc);
        switch (e) {
            .SUCCESS => return,
            .INTR => continue,
            else => {},
        }
        if (errno_out) |out| out.* = @intFromEnum(e);
        return switch (e) {
            .NOENT => error.NotFound,
            // kqueue_register returns EBADF for a bad target fd and for a bad
            // kqueue; the caller distinguishes by which fd it passed.
            .BADF => error.BadDescriptor,
            .INVAL => error.InvalidArgument,
            .SRCH => error.ProcessNotFound,
            .ACCES => error.AccessDenied,
            .NOMEM => error.SystemResources,
            .FAULT => error.InvalidArgument,
            else => error.Unexpected,
        };
    }
}

test "submitWait: EBADF and EINVAL are errors, not panics" {
    // The whole point of the wrapper: std.posix.kevent would panic here.
    const bad_kq: posix.fd_t = -1;
    var events: [1]Kevent = undefined;
    var errno_out: u32 = 0;
    var ts: posix.timespec = .{ .sec = 0, .nsec = 0 };
    try std.testing.expectError(
        error.KqueueInvalid,
        submitWait(bad_kq, &.{}, &events, &ts, &errno_out),
    );

    const kq = try posix.kqueue();
    defer posix.close(kq);
    ts.nsec = -1; // invalid timeout
    try std.testing.expectError(
        error.InvalidArgument,
        submitWait(kq, &.{}, &events, &ts, &errno_out),
    );
}

test "submitWait: a bad change returns an EV_ERROR record, not a failure" {
    // Eventlist room converts a rejected change into a record carrying errno
    // in data and the change's udata.
    const kq = try posix.kqueue();
    defer posix.close(kq);

    const del = Kevent{
        .ident = 4242,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.DELETE,
        .fflags = 0,
        .data = 0,
        .udata = 0xBEEF,
    };
    var events: [2]Kevent = undefined;
    var errno_out: u32 = 0;
    const n = try submitWait(kq, &.{del}, &events, null, &errno_out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(events[0].flags & std.c.EV.ERROR != 0);
    try std.testing.expectEqual(@as(usize, 0xBEEF), events[0].udata);
    try std.testing.expect(events[0].data > 0); // errno, ENOENT
}

test "applyNow: ENOENT on deleting a missing knote" {
    const kq = try posix.kqueue();
    defer posix.close(kq);

    const del = Kevent{
        .ident = 7777,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.DELETE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    };
    try std.testing.expectError(error.NotFound, applyNow(kq, &del, null));
}

test "applyNow: a valid trigger registers and fires" {
    // EVFILT_USER through applyNow, then harvest through submitWait.
    const kq = try posix.kqueue();
    defer posix.close(kq);

    const add = Kevent{
        .ident = 1,
        .filter = std.c.EVFILT.USER,
        .flags = std.c.EV.ADD,
        .fflags = 0,
        .data = 0,
        .udata = 0xAB,
    };
    try applyNow(kq, &add, null);
    // A trigger change would rewrite the knote's udata unless EV_KEEPUDATA
    // is passed; the kernel honors that flag on non-ADD changes
    // (kern_event.c), but repeating the udata here is simpler and just as
    // correct.
    const trigger = Kevent{
        .ident = 1,
        .filter = std.c.EVFILT.USER,
        .flags = 0,
        .fflags = std.c.NOTE.TRIGGER,
        .data = 0,
        .udata = 0xAB,
    };
    try applyNow(kq, &trigger, null);

    var events: [1]Kevent = undefined;
    var errno_out: u32 = 0;
    var ts: posix.timespec = .{ .sec = 1, .nsec = 0 };
    const n = try submitWait(kq, &.{}, &events, &ts, &errno_out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(std.c.EVFILT.USER, events[0].filter);
    try std.testing.expectEqual(@as(usize, 0xAB), events[0].udata);
}
