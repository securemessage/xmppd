//! # EventLoop — kqueue/kevent wrapper for event-driven daemons
//!
//! A thin, reusable abstraction over FreeBSD's kqueue(2) event notification system.
//! Designed for high-concurrency servers that manage thousands of persistent connections
//! (XMPP, WebSocket, IRC) without dedicating a thread or process to each one.
//!
//! ## Design Rationale
//!
//! XMPP connections are **persistent** — a user stays connected for hours or days, not
//! seconds like HTTP. A server with 10,000 online users needs 10,000 concurrent TCP streams.
//! Thread-per-connection would consume gigabytes of stack space and suffer context-switch
//! overhead. kqueue provides O(1) event dispatch regardless of connection count.
//!
//! ## Architecture
//!
//! - **Zero allocations in the hot path** — the event buffer is pre-allocated at init time.
//!   `poll()` returns a slice into this buffer; no allocation per call.
//! - **No global state** — multiple independent `EventLoop` instances are allowed.
//!   This enables future multi-threaded designs where each thread owns its own loop.
//! - **Typed event union** — consumers pattern-match on `Event` variants instead of
//!   interpreting raw `kevent` struct fields. This eliminates a class of bugs where
//!   filter type and data interpretation are mismatched.
//! - **Automatic signal masking** — `addSignal()` calls `sigprocmask()` to block the
//!   signal from default delivery, ensuring it's only received via kqueue.
//!
//! ## Future Portability
//!
//! This module targets FreeBSD's kqueue exclusively. A future `epoll` backend for Linux
//! would implement the same public API using `epoll_create1`, `epoll_ctl`, `epoll_wait`,
//! `signalfd`, and `timerfd_create`. The consumer code would not change.
//!
//! ## Example Usage
//!
//! ```zig
//! var loop = try EventLoop.init(std.heap.page_allocator, 256);
//! defer loop.deinit();
//!
//! // Register a listening socket for incoming connections
//! try loop.addFd(listen_fd, .read, @intFromPtr(my_listener));
//!
//! // Register graceful shutdown signal
//! try loop.addSignal(std.posix.SIG.TERM);
//!
//! // Main event loop
//! while (running) {
//!     const events = try loop.poll(null);
//!     for (events) |ev| {
//!         switch (ev) {
//!             .fd_readable => |e| handleRead(e),
//!             .fd_writable => |e| handleWrite(e),
//!             .timer => |t| handleTimeout(t),
//!             .signal => |s| if (s.signo == std.posix.SIG.TERM) running = false,
//!             .process_exit => |p| handleChildExit(p),
//!         }
//!     }
//! }
//! ```

const std = @import("std");
const posix = std.posix;

// ============================================================================
// Public Types
// ============================================================================

/// An event returned by `poll()`. Consumers switch on the active variant to
/// determine what happened and which resource it concerns.
pub const Event = union(enum) {
    /// A file descriptor (socket, pipe, etc.) has data available to read,
    /// or a listening socket has a new connection ready to accept.
    /// The `data` field contains the number of bytes available (for sockets)
    /// or the backlog count (for listeners).
    fd_readable: FdEvent,

    /// A file descriptor is ready for writing (buffer space available in the
    /// kernel send buffer). Register this when a non-blocking `write()` returns
    /// `EAGAIN`, and unregister when the write buffer is fully drained.
    fd_writable: FdEvent,

    /// A timer has fired. For one-shot timers, the timer is automatically
    /// removed after firing. For repeating timers, it will fire again after
    /// the configured interval.
    timer: TimerEvent,

    /// A signal was received. The signal was previously registered with
    /// `addSignal()` and is blocked from default delivery.
    signal: SignalEvent,

    /// A monitored child process has exited. The exit status is available
    /// in the `status` field.
    process_exit: ProcessEvent,

    /// An error occurred on a file descriptor (e.g., connection reset).
    /// The fd should be closed and cleaned up.
    fd_error: FdEvent,
};

/// Information about a file descriptor event.
pub const FdEvent = struct {
    /// The file descriptor that triggered the event.
    fd: posix.fd_t,
    /// Opaque user data associated with this fd (set during `addFd()`).
    /// Typically used to store a pointer to the connection object.
    udata: usize,
    /// Number of bytes available (read) or buffer space available (write).
    /// For listener sockets, this is the number of pending connections.
    data: i64,
};

/// Information about a timer event.
pub const TimerEvent = struct {
    /// The timer identifier (set during `addTimer()`).
    ident: usize,
    /// Number of times the timer has fired since last `poll()` call.
    /// Normally 1, but can be >1 if the event loop was delayed.
    overrun: i64,
};

/// Information about a signal event.
pub const SignalEvent = struct {
    /// The signal number (e.g., `std.posix.SIG.TERM`).
    signo: u32,
};

/// Information about a child process exit event.
pub const ProcessEvent = struct {
    /// The PID of the child process that exited.
    pid: posix.pid_t,
    /// The raw exit status (use `std.posix.W` helpers to interpret).
    status: u32,
};

/// Which I/O direction to monitor on a file descriptor.
pub const Filter = enum {
    /// Monitor for readability (data available, or new connection on listener).
    read,
    /// Monitor for writability (send buffer has space).
    write,
};

/// A descriptor for registering an fd with the event loop in bulk.
/// Used with `addFds()` and `removeFds()` to batch multiple fd
/// registrations into a single `kevent()` syscall.
pub const FdRegistration = struct {
    /// The file descriptor to register.
    fd: posix.fd_t,
    /// Which direction to monitor.
    filter: Filter,
    /// Opaque user data returned with events for this fd.
    udata: usize,
};

/// Accumulates a mixed batch of kqueue changes (adds, removes, enables,
/// disables, timers, signals) for submission in a single `kevent()` syscall.
///
/// This is the idiomatic way to use kqueue — build up a changelist during
/// your event processing loop, then flush everything (and wait) in one call.
///
/// ## Example
///
/// ```zig
/// var batch = ChangeList.init(&scratch_buf);
///
/// // Process events, accumulate changes
/// for (events) |ev| {
///     switch (ev) {
///         .fd_readable => |e| {
///             // Accepted a new connection — register it
///             batch.addRead(new_fd, conn_id) catch break;
///             // Done writing to old connection — stop monitoring writes
///             batch.removeWrite(old_fd) catch break;
///         },
///     }
/// }
///
/// // Flush all changes AND wait for next events — single syscall
/// const next_events = try loop.submitAndPoll(batch.slice(), null);
/// ```
pub const ChangeList = struct {
    buf: []posix.Kevent,
    len: usize = 0,

    /// Initialize a changelist backed by the given scratch buffer.
    /// The buffer determines the maximum number of changes per batch.
    pub fn init(buf: []posix.Kevent) ChangeList {
        return .{ .buf = buf };
    }

    /// Reset the changelist for reuse (zero-cost — just resets the length).
    pub fn reset(self: *ChangeList) void {
        self.len = 0;
    }

    /// Returns the accumulated changes as a slice for `submitAndPoll()`.
    pub fn slice(self: *const ChangeList) []const posix.Kevent {
        return self.buf[0..self.len];
    }

    /// Number of changes accumulated so far.
    pub fn count(self: *const ChangeList) usize {
        return self.len;
    }

    /// Add an fd for read monitoring.
    pub fn addRead(self: *ChangeList, fd: posix.fd_t, udata: usize) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, udata));
    }

    /// Add an fd for write monitoring.
    pub fn addWrite(self: *ChangeList, fd: posix.fd_t, udata: usize) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, udata));
    }

    /// Remove read monitoring for an fd.
    pub fn removeRead(self: *ChangeList, fd: posix.fd_t) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.READ, std.c.EV.DELETE, 0));
    }

    /// Remove write monitoring for an fd.
    pub fn removeWrite(self: *ChangeList, fd: posix.fd_t) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.DELETE, 0));
    }

    /// Add a one-shot read monitor (fires once when readable, then auto-removes).
    pub fn addReadOnce(self: *ChangeList, fd: posix.fd_t, udata: usize) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, udata));
    }

    /// Add a one-shot write monitor (fires once when writable, then auto-removes).
    /// Idiomatic for flush-on-demand: register when data is queued, fires once
    /// kernel send buffer has space.
    pub fn addWriteOnce(self: *ChangeList, fd: posix.fd_t, udata: usize) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, udata));
    }

    /// Enable read monitoring for an fd (must be previously added).
    pub fn enableRead(self: *ChangeList, fd: posix.fd_t) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ENABLE, 0));
    }

    /// Disable read monitoring for an fd without removing it.
    pub fn disableRead(self: *ChangeList, fd: posix.fd_t) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.READ, std.c.EV.DISABLE, 0));
    }

    /// Enable write monitoring for an fd (must be previously added).
    pub fn enableWrite(self: *ChangeList, fd: posix.fd_t) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ENABLE, 0));
    }

    /// Disable write monitoring for an fd without removing it.
    pub fn disableWrite(self: *ChangeList, fd: posix.fd_t) !void {
        try self.append(makeKevent(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.DISABLE, 0));
    }

    /// Add a one-shot or repeating timer.
    pub fn addTimer(self: *ChangeList, ident: usize, interval_ms: u32, one_shot: bool) !void {
        var flags: u16 = std.c.EV.ADD | std.c.EV.ENABLE;
        if (one_shot) flags |= std.c.EV.ONESHOT;
        var ev = makeKevent(ident, std.c.EVFILT.TIMER, flags, 0);
        ev.data = @intCast(interval_ms);
        try self.append(ev);
    }

    /// Remove a timer.
    pub fn removeTimer(self: *ChangeList, ident: usize) !void {
        try self.append(makeKevent(ident, std.c.EVFILT.TIMER, std.c.EV.DELETE, 0));
    }

    fn append(self: *ChangeList, ev: posix.Kevent) !void {
        if (self.len >= self.buf.len) return error.ChangeListFull;
        self.buf[self.len] = ev;
        self.len += 1;
    }
};

// ============================================================================
// EventLoop
// ============================================================================

/// A kqueue-based event loop for multiplexing I/O, timers, signals, and
/// process monitoring in a single thread.
///
/// Create one `EventLoop` per thread. All methods are NOT thread-safe —
/// an `EventLoop` must only be used from the thread that created it.
pub const EventLoop = struct {
    /// The kqueue file descriptor.
    kq: posix.fd_t,
    /// Pre-allocated buffer for receiving events from `kevent()`.
    event_buf: []posix.Kevent,
    /// Converted events returned to the caller (avoids allocation per poll).
    result_buf: []Event,
    /// Allocator used for buffer allocation (needed for deinit).
    allocator: std.mem.Allocator,

    /// Initialize a new event loop.
    ///
    /// `max_events` controls how many events can be returned per `poll()` call.
    /// A typical value is 64–256 for servers. Higher values reduce syscall
    /// frequency at the cost of more memory (each slot is ~64 bytes).
    ///
    /// ## Errors
    /// - `error.SystemResources` — kernel failed to allocate kqueue
    /// - `error.OutOfMemory` — allocator failed to allocate event buffers
    pub fn init(allocator: std.mem.Allocator, max_events: u16) !EventLoop {
        const kq = try posix.kqueue();
        errdefer posix.close(kq);

        const event_buf = try allocator.alloc(posix.Kevent, max_events);
        errdefer allocator.free(event_buf);

        const result_buf = try allocator.alloc(Event, max_events);

        return EventLoop{
            .kq = kq,
            .event_buf = event_buf,
            .result_buf = result_buf,
            .allocator = allocator,
        };
    }

    /// Destroy the event loop, closing the kqueue fd and freeing buffers.
    ///
    /// Any file descriptors, timers, or signals that were registered are
    /// implicitly unregistered when the kqueue fd is closed.
    pub fn deinit(self: *EventLoop) void {
        posix.close(self.kq);
        self.allocator.free(self.event_buf);
        self.allocator.free(self.result_buf);
        self.* = undefined;
    }

    /// Register a file descriptor for monitoring.
    ///
    /// - `fd` — the file descriptor to watch (socket, pipe, etc.)
    /// - `filter` — `.read` for readability, `.write` for writability
    /// - `udata` — opaque user data returned with events for this fd.
    ///   Typically `@intFromPtr(connection_ptr)` so you can cast back
    ///   in the event handler.
    ///
    /// The fd is monitored using `EV_ADD | EV_ENABLE`. If the fd is already
    /// registered for the same filter, this updates the udata.
    ///
    /// ## Errors
    /// - `error.FileDescriptorInvalid` — fd is not open
    /// - `error.SystemResources` — kernel resource exhaustion
    pub fn addFd(self: *EventLoop, fd: posix.fd_t, filter: Filter, udata: usize) !void {
        return self.addFdEx(fd, filter, udata, false);
    }

    /// Register a file descriptor for one-shot monitoring.
    ///
    /// Same as `addFd()` but the registration auto-removes after the first event
    /// fires. Ideal for write monitoring: register when data is queued, fires once
    /// when the kernel send buffer has space, then stops automatically.
    ///
    /// ## Errors
    /// - `error.FileDescriptorInvalid` — fd is not open
    /// - `error.SystemResources` — kernel resource exhaustion
    pub fn addFdOneshot(self: *EventLoop, fd: posix.fd_t, filter: Filter, udata: usize) !void {
        return self.addFdEx(fd, filter, udata, true);
    }

    fn addFdEx(self: *EventLoop, fd: posix.fd_t, filter: Filter, udata: usize, one_shot: bool) !void {
        const kfilter: i16 = switch (filter) {
            .read => std.c.EVFILT.READ,
            .write => std.c.EVFILT.WRITE,
        };

        var flags: u16 = std.c.EV.ADD | std.c.EV.ENABLE;
        if (one_shot) flags |= std.c.EV.ONESHOT;

        const changelist = [_]posix.Kevent{makeKevent(
            @intCast(fd),
            kfilter,
            flags,
            udata,
        )};

        try keventctl(self.kq, &changelist);
    }

    /// Remove a file descriptor from monitoring.
    ///
    /// - `fd` — the file descriptor to stop watching
    /// - `filter` — which filter to remove (`.read` or `.write`)
    ///
    /// It is safe to call this on an fd that is not registered (no-op).
    /// Note: closing an fd automatically removes all its kqueue registrations.
    ///
    /// ## Errors
    /// - `error.FileDescriptorInvalid` — fd is not open
    pub fn removeFd(self: *EventLoop, fd: posix.fd_t, filter: Filter) !void {
        const kfilter: i16 = switch (filter) {
            .read => std.c.EVFILT.READ,
            .write => std.c.EVFILT.WRITE,
        };

        const changelist = [_]posix.Kevent{makeKevent(
            @intCast(fd),
            kfilter,
            std.c.EV.DELETE,
            0,
        )};

        keventctl(self.kq, &changelist) catch |err| {
            // ENOENT means it wasn't registered — that's fine
            if (err == error.EventNotFound) return;
            return err;
        };
    }

    /// Enable or disable an existing fd registration without removing it.
    ///
    /// This is more efficient than `removeFd()` + `addFd()` when you need
    /// to temporarily pause monitoring (e.g., pause write monitoring after
    /// the write buffer drains, re-enable when new data arrives).
    ///
    /// - `fd` — the file descriptor
    /// - `filter` — which filter to modify
    /// - `enable` — `true` to enable, `false` to disable
    ///
    /// ## Errors
    /// - `error.FileDescriptorInvalid` — fd is not open
    /// - `error.EventNotFound` — fd was never registered for this filter
    pub fn modifyFd(self: *EventLoop, fd: posix.fd_t, filter: Filter, enable: bool) !void {
        const kfilter: i16 = switch (filter) {
            .read => std.c.EVFILT.READ,
            .write => std.c.EVFILT.WRITE,
        };

        const flags: u16 = if (enable) std.c.EV.ENABLE else std.c.EV.DISABLE;

        const changelist = [_]posix.Kevent{makeKevent(
            @intCast(fd),
            kfilter,
            flags,
            0,
        )};

        try keventctl(self.kq, &changelist);
    }

    /// Register multiple file descriptors in a single `kevent()` syscall.
    ///
    /// This is the bulk variant of `addFd()`. Use it when registering several
    /// fds at once (e.g., after accepting a batch of connections) to avoid
    /// per-fd syscall overhead.
    ///
    /// - `registrations` — slice of `FdRegistration` structs
    ///
    /// Requires a caller-provided scratch buffer to build the changelist.
    /// The buffer must be at least `registrations.len` elements.
    ///
    /// ## Errors
    /// - `error.SystemResources` — kernel resource exhaustion
    pub fn addFds(self: *EventLoop, registrations: []const FdRegistration, buf: []posix.Kevent) !void {
        std.debug.assert(buf.len >= registrations.len);
        for (registrations, 0..) |reg, i| {
            buf[i] = makeKevent(
                @intCast(reg.fd),
                switch (reg.filter) {
                    .read => std.c.EVFILT.READ,
                    .write => std.c.EVFILT.WRITE,
                },
                std.c.EV.ADD | std.c.EV.ENABLE,
                reg.udata,
            );
        }
        try keventctl(self.kq, buf[0..registrations.len]);
    }

    /// Remove multiple file descriptors in a single `kevent()` syscall.
    ///
    /// Bulk variant of `removeFd()`. Silently ignores fds that are not
    /// currently registered (same as `removeFd()`).
    ///
    /// - `registrations` — slice of `FdRegistration` structs (udata is ignored)
    /// - `buf` — scratch buffer, must be at least `registrations.len` elements
    ///
    /// ## Errors
    /// - `error.SystemResources` — kernel resource exhaustion
    pub fn removeFds(self: *EventLoop, registrations: []const FdRegistration, buf: []posix.Kevent) !void {
        std.debug.assert(buf.len >= registrations.len);
        for (registrations, 0..) |reg, i| {
            buf[i] = makeKevent(
                @intCast(reg.fd),
                switch (reg.filter) {
                    .read => std.c.EVFILT.READ,
                    .write => std.c.EVFILT.WRITE,
                },
                std.c.EV.DELETE,
                0,
            );
        }
        // Use raw kevent to tolerate ENOENT on individual entries.
        // When batching deletes, kqueue processes all entries even if some fail.
        var empty: [0]posix.Kevent = undefined;
        _ = posix.kevent(self.kq, buf[0..registrations.len], &empty, null) catch {};
    }

    /// Register a timer.
    ///
    /// - `ident` — unique identifier for this timer (caller-chosen, e.g., connection ID)
    /// - `interval_ms` — timer interval in milliseconds
    /// - `one_shot` — if `true`, the timer fires once and is automatically removed.
    ///   If `false`, the timer repeats at the given interval until explicitly removed.
    ///
    /// If a timer with the same `ident` already exists, it is replaced.
    ///
    /// ## Errors
    /// - `error.SystemResources` — too many timers
    pub fn addTimer(self: *EventLoop, ident: usize, interval_ms: u32, one_shot: bool) !void {
        var flags: u16 = std.c.EV.ADD | std.c.EV.ENABLE;
        if (one_shot) flags |= std.c.EV.ONESHOT;

        var ev = makeKevent(ident, std.c.EVFILT.TIMER, flags, 0);
        // NOTE_MSECONDS not defined in std.c; the default unit for EVFILT_TIMER
        // on FreeBSD is milliseconds, so we just set data directly.
        ev.data = @intCast(interval_ms);

        const changelist = [_]posix.Kevent{ev};
        try keventctl(self.kq, &changelist);
    }

    /// Remove a previously registered timer.
    ///
    /// - `ident` — the timer identifier passed to `addTimer()`
    ///
    /// It is safe to call this on a timer that has already fired (one-shot)
    /// or was never registered.
    pub fn removeTimer(self: *EventLoop, ident: usize) !void {
        const changelist = [_]posix.Kevent{makeKevent(
            ident,
            std.c.EVFILT.TIMER,
            std.c.EV.DELETE,
            0,
        )};

        keventctl(self.kq, &changelist) catch |err| {
            if (err == error.EventNotFound) return;
            return err;
        };
    }

    /// Register a signal for delivery via the event loop.
    ///
    /// The signal is automatically blocked from default delivery using
    /// `sigprocmask(SIG_BLOCK)`. This ensures the signal is only received
    /// as a kqueue event, preventing race conditions with default handlers.
    ///
    /// - `signo` — signal number (e.g., `posix.SIG.TERM`, `posix.SIG.HUP`)
    ///
    /// ## Common signals for daemons:
    /// - `SIGTERM` — graceful shutdown
    /// - `SIGHUP` — configuration reload
    /// - `SIGINT` — interactive interrupt (dev mode)
    /// - `SIGUSR1` / `SIGUSR2` — application-defined
    ///
    /// ## Errors
    /// - `error.SystemResources` — kernel resource exhaustion
    pub fn addSignal(self: *EventLoop, signo: u8) !void {
        // Block the signal from default delivery
        var mask = posix.sigemptyset();
        posix.sigaddset(&mask, signo);
        posix.sigprocmask(posix.SIG.BLOCK, &mask, null);

        const changelist = [_]posix.Kevent{makeKevent(
            @intCast(signo),
            std.c.EVFILT.SIGNAL,
            std.c.EV.ADD | std.c.EV.ENABLE,
            0,
        )};

        try keventctl(self.kq, &changelist);
    }

    /// Monitor a child process for exit.
    ///
    /// When the process exits, a `process_exit` event is returned by `poll()`
    /// containing the PID and exit status. The registration is automatically
    /// removed after the event fires (one-shot).
    ///
    /// - `pid` — the process ID to monitor (must be a child of this process)
    ///
    /// ## Errors
    /// - `error.ProcessNotFound` — the PID does not exist or is not a child
    /// - `error.SystemResources` — kernel resource exhaustion
    pub fn addProcess(self: *EventLoop, pid: posix.pid_t) !void {
        var ev = makeKevent(
            @intCast(pid),
            std.c.EVFILT.PROC,
            std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
            0,
        );
        ev.fflags = std.c.NOTE.EXIT;
        const changelist = [_]posix.Kevent{ev};
        try keventctl(self.kq, &changelist);
    }

    /// Wait for events and return them.
    ///
    /// Blocks until at least one event is ready, or until `timeout_ms`
    /// milliseconds have elapsed. Pass `null` for `timeout_ms` to block
    /// indefinitely.
    ///
    /// Returns a slice of events valid until the next call to `poll()`.
    /// The slice references an internal buffer — do not store it across calls.
    ///
    /// This is the simple API for the common case. If you need to register
    /// new fds and wait in a single syscall (e.g., after accepting a burst
    /// of connections), use `submitAndPoll()` instead.
    ///
    /// ## Errors
    /// - `error.SystemResources` — kernel error
    pub fn poll(self: *EventLoop, timeout_ms: ?u32) ![]const Event {
        var empty_changelist: [0]posix.Kevent = undefined;
        return self.submitAndPoll(&empty_changelist, timeout_ms);
    }

    /// Submit pending changes AND wait for events in a single `kevent()` syscall.
    ///
    /// The raw `kevent(2)` syscall accepts both a changelist (registrations to
    /// add/remove/modify) and an eventlist (buffer for ready events) atomically.
    /// This method exposes that capability for callers that need to batch
    /// modifications with the wait — avoiding extra syscalls.
    ///
    /// **When to use this instead of `poll()`:**
    /// - After accepting a burst of new connections (batch all `EV_ADD`s)
    /// - When toggling write interest on multiple connections at once
    /// - Any time you'd otherwise call `addFd()`/`removeFd()` in a loop
    ///   followed by `poll()`
    ///
    /// The `changelist` contains raw `posix.Kevent` structs. Use the top-level
    /// `makeChangeEvent()` function to construct them with the correct field layout.
    ///
    /// Returns a slice of events valid until the next call to `poll()` or
    /// `submitAndPoll()`.
    ///
    /// ## Errors
    /// - `error.SystemResources` — kernel error or changelist contained invalid entries
    pub fn submitAndPoll(
        self: *EventLoop,
        changelist: []const posix.Kevent,
        timeout_ms: ?u32,
    ) ![]const Event {
        const timeout: ?posix.timespec = if (timeout_ms) |ms| posix.timespec{
            .sec = @intCast(ms / 1000),
            .nsec = @intCast((@as(u64, ms % 1000)) * 1_000_000),
        } else null;

        const timeout_ptr: ?*const posix.timespec = if (timeout) |*t| t else null;

        const count = posix.kevent(self.kq, changelist, self.event_buf, timeout_ptr) catch |err| {
            return switch (err) {
                error.EventNotFound => error.SystemResources,
                error.AccessDenied => error.SystemResources,
                error.ProcessNotFound => error.SystemResources,
                error.SystemResources => error.SystemResources,
                error.Overflow => error.SystemResources,
            };
        };

        // Convert raw kevents to typed Event union
        for (self.event_buf[0..count], 0..) |kev, i| {
            self.result_buf[i] = translateKevent(kev);
        }

        return self.result_buf[0..count];
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    fn translateKevent(kev: posix.Kevent) Event {
        // Check for errors first
        if (kev.flags & std.c.EV.ERROR != 0) {
            return .{ .fd_error = .{
                .fd = @intCast(kev.ident),
                .udata = kev.udata,
                .data = kev.data,
            } };
        }

        return switch (kev.filter) {
            std.c.EVFILT.READ => .{ .fd_readable = .{
                .fd = @intCast(kev.ident),
                .udata = kev.udata,
                .data = kev.data,
            } },
            std.c.EVFILT.WRITE => .{ .fd_writable = .{
                .fd = @intCast(kev.ident),
                .udata = kev.udata,
                .data = kev.data,
            } },
            std.c.EVFILT.TIMER => .{ .timer = .{
                .ident = kev.ident,
                .overrun = kev.data,
            } },
            std.c.EVFILT.SIGNAL => .{ .signal = .{
                .signo = @intCast(kev.ident),
            } },
            std.c.EVFILT.PROC => .{ .process_exit = .{
                .pid = @intCast(kev.ident),
                .status = @intCast(kev.data),
            } },
            else => .{ .fd_error = .{
                .fd = @intCast(kev.ident),
                .udata = kev.udata,
                .data = kev.data,
            } },
        };
    }
};

// ============================================================================
// Internal helpers
// ============================================================================

/// Construct a raw `posix.Kevent` struct for use with `submitAndPoll()`.
///
/// This is a convenience helper that fills in the common fields and zeros
/// the rest. For most use cases, prefer the typed methods (`addFd`, `addTimer`,
/// etc.). Use this only when building a changelist for `submitAndPoll()`.
///
/// ## Example: batch-register two fds for reading
/// ```zig
/// const changes = [_]posix.Kevent{
///     makeChangeEvent(@intCast(fd1), .read, std.c.EV.ADD | std.c.EV.ENABLE, conn1_id),
///     makeChangeEvent(@intCast(fd2), .read, std.c.EV.ADD | std.c.EV.ENABLE, conn2_id),
/// };
/// const events = try loop.submitAndPoll(&changes, null);
/// ```
pub fn makeChangeEvent(ident: usize, filter: Filter, flags: u16, udata: usize) posix.Kevent {
    return makeKevent(ident, switch (filter) {
        .read => std.c.EVFILT.READ,
        .write => std.c.EVFILT.WRITE,
    }, flags, udata);
}

/// Construct a kevent struct with common fields. Internal helper.
fn makeKevent(ident: usize, filter: i16, flags: u16, udata: usize) posix.Kevent {
    return .{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = 0,
        .data = 0,
        .udata = udata,
    };
}

/// Submit a changelist to kqueue. Thin wrapper over posix.kevent().
fn keventctl(kq: posix.fd_t, changelist: []const posix.Kevent) !void {
    var empty: [0]posix.Kevent = undefined;
    _ = posix.kevent(kq, changelist, &empty, null) catch |err| {
        return switch (err) {
            error.EventNotFound => error.EventNotFound,
            error.AccessDenied => error.SystemResources,
            error.ProcessNotFound => error.ProcessNotFound,
            error.SystemResources => error.SystemResources,
            error.Overflow => error.SystemResources,
        };
    };
}

// ============================================================================
// Tests
// ============================================================================

test "EventLoop: init and deinit" {
    var loop = try EventLoop.init(std.testing.allocator, 64);
    defer loop.deinit();

    // kqueue fd should be valid
    try std.testing.expect(loop.kq >= 0);
}

test "EventLoop: fd_readable fires on pipe write" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Create a pipe
    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Register read end for readability
    try loop.addFd(pipe_fds[0], .read, 0xDEAD);

    // Write some data to the pipe
    _ = try posix.write(pipe_fds[1], "hello");

    // Poll should return a readable event
    const events = try loop.poll(100);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_readable);
    try std.testing.expectEqual(pipe_fds[0], events[0].fd_readable.fd);
    try std.testing.expectEqual(@as(usize, 0xDEAD), events[0].fd_readable.udata);
    try std.testing.expect(events[0].fd_readable.data >= 5); // at least 5 bytes available
}

test "EventLoop: fd_writable fires on socket" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Create a pipe — write end is always writable initially
    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Register write end for writability
    try loop.addFd(pipe_fds[1], .write, 0xBEEF);

    // Poll should return a writable event immediately
    const events = try loop.poll(100);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_writable);
    try std.testing.expectEqual(pipe_fds[1], events[0].fd_writable.fd);
    try std.testing.expectEqual(@as(usize, 0xBEEF), events[0].fd_writable.udata);
}

test "EventLoop: removeFd stops events" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    try loop.addFd(pipe_fds[0], .read, 0);
    try loop.removeFd(pipe_fds[0], .read);

    // Write data — should NOT trigger an event
    _ = try posix.write(pipe_fds[1], "data");

    // Poll with short timeout — should return empty
    const events = try loop.poll(50);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "EventLoop: timer one-shot" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Add a 50ms one-shot timer
    try loop.addTimer(42, 50, true);

    // Poll with 200ms timeout — timer should fire
    const events = try loop.poll(200);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .timer);
    try std.testing.expectEqual(@as(usize, 42), events[0].timer.ident);

    // Poll again — timer was one-shot, should NOT fire again
    const events2 = try loop.poll(100);
    try std.testing.expectEqual(@as(usize, 0), events2.len);
}

test "EventLoop: timer repeating" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Add a 30ms repeating timer
    try loop.addTimer(99, 30, false);

    // Wait enough for at least 2 fires
    std.Thread.sleep(80 * std.time.ns_per_ms);

    const events = try loop.poll(0);
    try std.testing.expect(events.len >= 1);
    try std.testing.expect(events[0] == .timer);
    try std.testing.expectEqual(@as(usize, 99), events[0].timer.ident);

    // Clean up
    try loop.removeTimer(99);
}

test "EventLoop: signal delivery" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Register SIGUSR1
    try loop.addSignal(posix.SIG.USR1);

    // Send signal to self
    try posix.raise(posix.SIG.USR1);

    // Poll should return signal event
    const events = try loop.poll(100);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .signal);
    try std.testing.expectEqual(@as(u32, posix.SIG.USR1), events[0].signal.signo);
}

test "EventLoop: process exit monitoring" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Fork a child that exits immediately
    const pid = try posix.fork();
    if (pid == 0) {
        // Child — exit with code 42
        posix.exit(42);
    }

    // Parent — monitor the child
    try loop.addProcess(pid);

    // Poll should return process exit event
    const events = try loop.poll(1000);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .process_exit);
    try std.testing.expectEqual(pid, events[0].process_exit.pid);

    // Reap the child to avoid zombies
    _ = posix.waitpid(pid, 0);
}

test "EventLoop: poll timeout returns empty" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Poll with 10ms timeout, nothing registered — should return empty
    const events = try loop.poll(10);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "EventLoop: addFds bulk registration" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Create 3 pipes
    const p1 = try posix.pipe();
    defer posix.close(p1[0]);
    defer posix.close(p1[1]);
    const p2 = try posix.pipe();
    defer posix.close(p2[0]);
    defer posix.close(p2[1]);
    const p3 = try posix.pipe();
    defer posix.close(p3[0]);
    defer posix.close(p3[1]);

    // Bulk-register all 3 read ends in a single syscall
    const regs = [_]FdRegistration{
        .{ .fd = p1[0], .filter = .read, .udata = 1 },
        .{ .fd = p2[0], .filter = .read, .udata = 2 },
        .{ .fd = p3[0], .filter = .read, .udata = 3 },
    };
    var buf: [3]posix.Kevent = undefined;
    try loop.addFds(&regs, &buf);

    // Write to pipe 2 only
    _ = try posix.write(p2[1], "hello");

    // Should get exactly 1 event with udata=2
    const events = try loop.poll(100);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_readable);
    try std.testing.expectEqual(@as(usize, 2), events[0].fd_readable.udata);
}

test "EventLoop: removeFds bulk removal" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    const p1 = try posix.pipe();
    defer posix.close(p1[0]);
    defer posix.close(p1[1]);
    const p2 = try posix.pipe();
    defer posix.close(p2[0]);
    defer posix.close(p2[1]);

    // Register both
    try loop.addFd(p1[0], .read, 10);
    try loop.addFd(p2[0], .read, 20);

    // Bulk-remove both in a single syscall
    const regs = [_]FdRegistration{
        .{ .fd = p1[0], .filter = .read, .udata = 0 },
        .{ .fd = p2[0], .filter = .read, .udata = 0 },
    };
    var buf: [2]posix.Kevent = undefined;
    try loop.removeFds(&regs, &buf);

    // Write to both — should NOT trigger
    _ = try posix.write(p1[1], "data");
    _ = try posix.write(p2[1], "data");
    const events = try loop.poll(50);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "EventLoop: submitAndPoll batches add + wait" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    const p1 = try posix.pipe();
    defer posix.close(p1[0]);
    defer posix.close(p1[1]);

    // Write data BEFORE registering
    _ = try posix.write(p1[1], "pre-written");

    // Register AND wait in a single syscall
    const changes = [_]posix.Kevent{
        makeChangeEvent(@intCast(p1[0]), .read, std.c.EV.ADD | std.c.EV.ENABLE, 0xCAFE),
    };
    const events = try loop.submitAndPoll(&changes, 100);

    // Should see the pre-written data immediately
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_readable);
    try std.testing.expectEqual(@as(usize, 0xCAFE), events[0].fd_readable.udata);
}

test "ChangeList: mixed add + remove in single syscall" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    // Create 2 pipes
    const p1 = try posix.pipe();
    defer posix.close(p1[0]);
    defer posix.close(p1[1]);
    const p2 = try posix.pipe();
    defer posix.close(p2[0]);
    defer posix.close(p2[1]);

    // Register p1 for reading (using single-fd API)
    try loop.addFd(p1[0], .read, 1);

    // Write to both pipes
    _ = try posix.write(p1[1], "pipe1");
    _ = try posix.write(p2[1], "pipe2");

    // Now build a batch that REMOVES p1 and ADDS p2 — single syscall
    var scratch: [4]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);
    try batch.removeRead(p1[0]);
    try batch.addRead(p2[0], 2);
    try std.testing.expectEqual(@as(usize, 2), batch.count());

    // Flush changes and wait — one kevent() call
    const events = try loop.submitAndPoll(batch.slice(), 100);

    // Only p2 should fire (p1 was removed)
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_readable);
    try std.testing.expectEqual(@as(usize, 2), events[0].fd_readable.udata);
}

test "ChangeList: reset and reuse" {
    var scratch: [4]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);

    try batch.addRead(5, 100);
    try batch.addWrite(6, 200);
    try std.testing.expectEqual(@as(usize, 2), batch.count());

    batch.reset();
    try std.testing.expectEqual(@as(usize, 0), batch.count());
    try std.testing.expectEqual(@as(usize, 0), batch.slice().len);

    // Can reuse after reset
    try batch.removeRead(5);
    try std.testing.expectEqual(@as(usize, 1), batch.count());
}

test "ChangeList: overflow returns error" {
    var scratch: [2]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);

    try batch.addRead(1, 0);
    try batch.addRead(2, 0);
    try std.testing.expectError(error.ChangeListFull, batch.addRead(3, 0));
}

test "EventLoop: addFdOneshot fires once then stops" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Register write end as one-shot writable
    try loop.addFdOneshot(pipe_fds[1], .write, 0xFACE);

    // Poll — should fire immediately (pipe is writable)
    const events = try loop.poll(100);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_writable);
    try std.testing.expectEqual(@as(usize, 0xFACE), events[0].fd_writable.udata);

    // Poll again — one-shot should have auto-removed, no more events
    const events2 = try loop.poll(50);
    try std.testing.expectEqual(@as(usize, 0), events2.len);
}

test "ChangeList: addWriteOnce fires once then stops" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Use ChangeList to add one-shot write monitor
    var scratch: [4]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);
    try batch.addWriteOnce(pipe_fds[1], 0xD00D);

    const events = try loop.submitAndPoll(batch.slice(), 100);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(events[0] == .fd_writable);
    try std.testing.expectEqual(@as(usize, 0xD00D), events[0].fd_writable.udata);

    // Second poll — auto-removed
    const events2 = try loop.poll(50);
    try std.testing.expectEqual(@as(usize, 0), events2.len);
}

test "EventLoop: modifyFd disable and enable" {
    var loop = try EventLoop.init(std.testing.allocator, 16);
    defer loop.deinit();

    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Add and immediately disable
    try loop.addFd(pipe_fds[0], .read, 0);
    try loop.modifyFd(pipe_fds[0], .read, false);

    // Write data — should NOT trigger (disabled)
    _ = try posix.write(pipe_fds[1], "test");
    const events1 = try loop.poll(50);
    try std.testing.expectEqual(@as(usize, 0), events1.len);

    // Re-enable — should now fire
    try loop.modifyFd(pipe_fds[0], .read, true);
    const events2 = try loop.poll(50);
    try std.testing.expectEqual(@as(usize, 1), events2.len);
    try std.testing.expect(events2[0] == .fd_readable);
}
