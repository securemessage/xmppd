//! # LMDB Storage Backend
//!
//! Implements the StorageBackend trait using LMDB (via zig-lmdb).
//! Namespaces map to LMDB named databases (DBI handles): the canonical set
//! (backend.canonical_namespaces) is opened at startup under one write
//! transaction; any other namespace is created lazily under dbi_lock (S9 -
//! cache mutation is mutex-guarded, and the env map size is never resized
//! at runtime because LMDB documents that as unsafe with open read txns;
//! MAP_FULL surfaces as an error, tune via [server] lmdb_map_size_mb).

const std = @import("std");
const builtin = @import("builtin");
const lmdb = @import("lmdb");
const backend = @import("backend");

// LMDB C API supplement: the zig-lmdb wrapper's Environment.info() drops
// me_last_pgno, which is the only reliable "how much of the map is in use"
// measure (mdb_env_stat covers MAIN_DBI only, S9).
const MdbEnvInfoC = extern struct {
    me_mapaddr: usize,
    me_mapsize: usize,
    me_last_pgno: usize,
    me_last_txnid: usize,
    me_maxreaders: c_uint,
    me_numreaders: c_uint,
};
extern "c" fn mdb_env_info(env: ?*anyopaque, info: *MdbEnvInfoC) c_int;
extern "c" fn mdb_env_get_fd(env: ?*anyopaque, fd: *c_int) c_int;

// sysctl kern.proc.vmmap record prefix (sys/user.h kinfo_vmentry).
// Records are walked by kve_structsize: kve_path is truncated on
// copyout, so sizeof here is only the fixed prefix actually read.
const KinfoVmentry = extern struct {
    kve_structsize: c_int,
    kve_type: c_int,
    kve_start: u64,
    kve_end: u64,
    kve_offset: u64,
    kve_vn_fileid: u64,
    kve_vn_fsid_freebsd11: u32,
    kve_flags: c_int,
    kve_resident: c_int,
    kve_private_resident: c_int,
    kve_protection: c_int,
    kve_ref_count: c_int,
    kve_shadow_count: c_int,
    kve_vn_type: c_int,
    kve_vn_size: u64,
    kve_vn_rdev_freebsd11: u32,
    kve_vn_mode: u16,
    kve_status: u16,
    kve_vn_fsid: u64,
    kve_vn_rdev: u64,
};
const KVME_TYPE_VNODE = 2;
const KVME_FLAG_NOCOREDUMP = 0x4;
const VMMAP_ATTEMPTS_MAX = 3;
const VMMAP_BUF_SLACK = 4096;

// kern.proc.vmmap seam: tests can substitute synthetic records and ENOMEM
// failures so the bounded retry can be checked without racing mappings.
const vmmapCall = if (builtin.is_test) struct {
    var stub = false;
    var size_calls: usize = 0;
    var read_calls: usize = 0;
    var read_fails: usize = 0;
    var read_error: std.posix.SysCtlError = error.SystemResources;
    var records: []const u8 = &.{};

    fn reset() void {
        stub = false;
        size_calls = 0;
        read_calls = 0;
        read_fails = 0;
        read_error = error.SystemResources;
        records = &.{};
    }

    fn size(mib: []const c_int, len: *usize) std.posix.SysCtlError!void {
        if (!stub) return std.posix.sysctl(mib, null, len, null, 0);
        size_calls += 1;
        len.* = records.len;
    }

    fn read(mib: []const c_int, buf: []u8, len: *usize) std.posix.SysCtlError!void {
        if (!stub) {
            len.* = buf.len;
            return std.posix.sysctl(mib, buf.ptr, len, null, 0);
        }
        read_calls += 1;
        if (read_fails != 0) {
            read_fails -= 1;
            return read_error;
        }
        if (records.len > buf.len) return error.SystemResources;
        @memcpy(buf[0..records.len], records);
        len.* = records.len;
    }
} else struct {
    fn size(mib: []const c_int, len: *usize) std.posix.SysCtlError!void {
        return std.posix.sysctl(mib, null, len, null, 0);
    }

    fn read(mib: []const c_int, buf: []u8, len: *usize) std.posix.SysCtlError!void {
        len.* = buf.len;
        return std.posix.sysctl(mib, buf.ptr, len, null, 0);
    }
};

// madvise seam: test builds record the arguments instead of advising the
// kernel, so a test can check the advised range covers the env map.
// A nonzero result also sets a deterministic errno so the warn log does
// not print a stale value.
const madviseCall = if (builtin.is_test) struct {
    var calls: usize = 0;
    var addr: usize = 0;
    var len: usize = 0;
    var advice: u32 = 0;
    var result: c_int = 0;
    var result_errno: c_int = @intFromEnum(std.posix.E.INVAL);

    fn run(a: usize, l: usize, adv: u32) c_int {
        calls += 1;
        addr = a;
        len = l;
        advice = adv;
        if (result != 0) std.c._errno().* = result_errno;
        return result;
    }
} else struct {
    fn run(a: usize, l: usize, adv: u32) c_int {
        const ptr: *align(std.heap.page_size_min) anyopaque = @ptrFromInt(a);
        return std.c.madvise(ptr, l, adv);
    }
};

const log = std.log.scoped(.lmdb_store);

// warn seam: test builds count the exhaustion warning so its distinct
// message can be checked without scraping stderr.
const warnCall = struct {
    var exhausted_calls: usize = 0;

    fn exhausted() void {
        if (builtin.is_test) exhausted_calls += 1;
        log.warn(
            "kern.proc.vmmap lookup failed after {d} attempts: LMDB map stays in core dumps",
            .{VMMAP_ATTEMPTS_MAX},
        );
    }
};

/// Exclude the env map from core dumps: a crash would otherwise write
/// every touched LMDB page (SCRAM keys, rosters, archive contents) into
/// the core file. LMDB reports me_mapaddr only for MDB_FIXEDMAP envs,
/// so the map range comes from the process VM map instead: the vnode
/// entry whose inode and filesystem id match the env's data file
/// (mdb_env_get_fd). One call covers the map's lifetime because the map
/// is never resized at runtime (S9, T358); failure is logged once and
/// does not fail the open.
fn excludeMapFromCoreDump(env: lmdb.Environment) void {
    var fd: c_int = 0;
    if (mdb_env_get_fd(env.ptr, &fd) != 0) {
        log.warn("mdb_env_get_fd failed: LMDB map stays in core dumps", .{});
        return;
    }
    const st = std.posix.fstat(fd) catch {
        log.warn("fstat on the LMDB data fd failed: map stays in core dumps", .{});
        return;
    };
    const rec = (findVmEntry(st.ino, st.dev) catch {
        warnCall.exhausted();
        return;
    }) orelse {
        log.warn("LMDB map not found in kern.proc.vmmap: map stays in core dumps", .{});
        return;
    };
    const start: usize = @intCast(rec.kve_start);
    const len: usize = @intCast(rec.kve_end - rec.kve_start);
    const rc = madviseCall.run(start, len, std.c.MADV.NOCORE);
    if (rc != 0) {
        log.warn("madvise MADV_NOCORE on the LMDB map failed (errno {d}): map stays in core dumps", .{@intFromEnum(std.posix.errno(rc))});
    }
}

/// Fixed prefix of the VMA record backed by the vnode (ino, fsid), or
/// null when kern.proc.vmmap yields no match. Other threads can add
/// mappings between the size query and the read, so ENOMEM retries are
/// bounded by VMMAP_ATTEMPTS_MAX; exhausting them is reported as
/// error.AttemptsExhausted so the caller can warn about the bound itself.
fn findVmEntry(ino: u64, fsid: u64) error{AttemptsExhausted}!?KinfoVmentry {
    var mib = [_]c_int{ 1, 14, 32, std.c.getpid() }; // CTL_KERN, KERN_PROC, KERN_PROC_VMMAP
    var attempt: usize = 0;
    while (attempt < VMMAP_ATTEMPTS_MAX) : (attempt += 1) {
        var len: usize = 0;
        vmmapCall.size(&mib, &len) catch |err| {
            switch (err) {
                error.SystemResources => continue,
                else => return null,
            }
        };

        const buf_len = std.math.add(usize, len, VMMAP_BUF_SLACK) catch return null;
        const buf = std.heap.page_allocator.alloc(u8, buf_len) catch return null;
        var out_len = buf.len;
        vmmapCall.read(&mib, buf, &out_len) catch |err| {
            std.heap.page_allocator.free(buf);
            switch (err) {
                error.SystemResources => continue,
                else => return null,
            }
        };

        const rec = findVmRecord(buf[0..out_len], ino, fsid);
        std.heap.page_allocator.free(buf);
        return rec;
    }
    return error.AttemptsExhausted;
}

/// First vnode record in a kern.proc.vmmap buffer whose inode and
/// filesystem id both match. Inode numbers are per filesystem (ZFS
/// object numbers repeat across datasets), so an inode-only match can
/// pick an unrelated mapping and leave the env map in core dumps.
fn findVmRecord(buf: []const u8, ino: u64, fsid: u64) ?KinfoVmentry {
    var off: usize = 0;
    while (off + @sizeOf(KinfoVmentry) <= buf.len) {
        const rec: *align(1) const KinfoVmentry = @ptrCast(buf.ptr + off);
        const size: usize = @intCast(rec.kve_structsize);
        if (size < @sizeOf(KinfoVmentry)) break;
        if (rec.kve_type == KVME_TYPE_VNODE and rec.kve_vn_fileid == ino and rec.kve_vn_fsid == fsid)
            return rec.*;
        off += size;
    }
    return null;
}

const MAX_DBS = 24;

const DbiCacheEntry = struct {
    name_buf: [64]u8,
    name_len: u8,
    dbi: lmdb.Database.DBI,
};

pub const Backend = LmdbBackend;

pub const LmdbBackend = struct {
    env: lmdb.Environment,
    dbi_cache: [MAX_DBS]DbiCacheEntry,
    /// Cache append counter; acquire/release so the canonical prefixes are
    /// readable without any lock after open() (S9).
    dbi_count: std.atomic.Value(u32) = .init(0),
    map_size: usize,
    compound_mutex: std.Thread.Mutex = .{},
    /// Guards dbi_cache appends only. Never held across a call that begins
    /// an LMDB write txn (txn begin takes the LMDB writer lock while a
    /// WriteBatch holder waits for dbi_lock).
    dbi_lock: std.Thread.Mutex = .{},
    /// Set once the 80% warning has fired.
    usage_warned: std.atomic.Value(bool) = .init(false),
    /// Offline tools hold an exclusive byte-0 lock on lock.mdb for the whole
    /// environment lifetime. Closing any descriptor of the file while the
    /// env is open would release every fcntl lock this process holds on it,
    /// including LMDB's own (D5), so this is closed only after env.deinit().
    lock_file: ?std.fs.File = null,

    /// A read runs inside its own read txn, which LMDB pins to an MVCC
    /// snapshot, so it cannot observe a half-applied write and does not need
    /// the store's compound lock (S9).
    pub const reads_are_snapshot = true;

    comptime {
        backend.assertBackend(LmdbBackend);
    }

    pub fn open(path: []const u8, opts: backend.OpenOptions) !LmdbBackend {
        return openInternal(path, opts, null);
    }

    /// Open an environment for an offline tool (migrate-precis, deluser
    /// --raw). The exclusive byte-0 lock is taken before the environment
    /// exists and held until after env.deinit(): opening a second descriptor
    /// after env open and closing it would drop every fcntl lock this
    /// process holds on lock.mdb, including LMDB's own (D5). A daemon that
    /// starts mid-run blocks in its env open; when the offline tool exits,
    /// LMDB on FreeBSD destroys its shared mutexes, so that daemon then
    /// fails with EINVAL and must be restarted after xmppctl exits.
    pub fn openOffline(path: []const u8, opts: backend.OpenOptions) !LmdbBackend {
        if (opts.create) {
            std.fs.cwd().makePath(path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
        const lock_file = try acquireOfflineLock(path, opts.create);
        return openInternal(path, opts, lock_file);
    }

    fn openInternal(path: []const u8, opts: backend.OpenOptions, lock_file: ?std.fs.File) !LmdbBackend {
        var owned_lock = lock_file;
        errdefer if (owned_lock) |file| file.close();

        if (opts.create) {
            std.fs.cwd().makePath(path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        var path_buf: [4096]u8 = undefined;
        if (path.len >= path_buf.len) return error.NameTooLong;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;

        const env = try lmdb.Environment.init(
            @ptrCast(path_buf[0..path.len :0]),
            .{
                .map_size = opts.map_size,
                .max_dbs = opts.max_namespaces,
                .read_only = opts.read_only,
            },
        );
        // A failed namespace open must not leave the env behind: a leaked
        // handle keeps the data/lock fds open, and the provisioning pass
        // that follows the failure then runs a second env on the same
        // files, where LMDB drops the process's lock-file locks (D5).
        errdefer env.deinit();
        excludeMapFromCoreDump(env);

        // Env open may briefly downgrade byte 0 to a shared lock. Re-take
        // the exclusive lock before any namespace write and keep it for the
        // whole run.
        if (owned_lock) |file| try setExclusiveLock(file.handle);

        var self: LmdbBackend = .{
            .env = env,
            .dbi_cache = undefined,
            .dbi_count = .init(0),
            .map_size = opts.map_size,
            .lock_file = owned_lock,
        };
        if (!opts.read_only) try self.openCanonicalNamespaces() else try self.openCanonicalNamespacesReadOnly();
        owned_lock = null;
        self.warnIfNearlyFull();
        return self;
    }

    fn acquireOfflineLock(path: []const u8, create: bool) !std.fs.File {
        var lock_path_buf: [4096]u8 = undefined;
        const lock_path = std.fmt.bufPrint(&lock_path_buf, "{s}/lock.mdb", .{path}) catch
            return error.NameTooLong;
        var file = std.fs.cwd().openFile(lock_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => if (create)
                std.fs.cwd().createFile(lock_path, .{ .read = true, .truncate = false }) catch
                    return error.LmdbCheckFailed
            else
                return error.LmdbCheckFailed,
            error.AccessDenied => return error.LmdbCheckFailed,
            else => return err,
        };
        errdefer file.close();
        try setExclusiveLock(file.handle);
        return file;
    }

    fn setExclusiveLock(handle: std.posix.fd_t) !void {
        var lock: std.posix.Flock = .{
            .start = 0,
            .len = 1,
            .pid = 0,
            .type = std.c.F.WRLCK,
            .whence = 0,
            .sysid = 0,
        };
        const rc = std.c.fcntl(handle, std.c.F.SETLK, &lock);
        if (rc == -1) {
            return switch (std.posix.errno(rc)) {
                .ACCES, .AGAIN => error.DaemonsRunning,
                else => error.LmdbCheckFailed,
            };
        }
    }

    /// Open every canonical namespace in one write transaction (S9): no
    /// worker thread creates a DBI mid-operation, so the cache races in
    /// getOrCreateDbi/resolveDbi can only ever fire for a genuinely new
    /// (test-only) namespace.
    // No errdefer+commit pairing: mdb_txn_commit aborts the txn itself on
    // failure, so an errdefer abort() would end the write txn twice on
    // exactly the MAP_FULL/ENOSPC path that matters (S9).
    fn openCanonicalNamespaces(self: *LmdbBackend) !void {
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        for (backend.canonical_namespaces) |ns| {
            var name_z: [65]u8 = undefined;
            if (ns.len > 64) {
                txn.abort();
                return error.MDB_BAD_VALSIZE;
            }
            @memcpy(name_z[0..ns.len], ns);
            name_z[ns.len] = 0;
            const db = lmdb.Database.open(txn, @ptrCast(name_z[0..ns.len :0]), .{ .create = true }) catch |err| {
                txn.abort();
                return err;
            };
            const entry = &self.dbi_cache[self.dbi_count.load(.monotonic)];
            @memcpy(entry.name_buf[0..ns.len], ns);
            entry.name_len = @intCast(ns.len);
            entry.dbi = db.dbi;
            self.dbi_count.store(self.dbi_count.load(.monotonic) + 1, .release);
        }
        try txn.commit();
    }

    /// Read-only openings (the OIDC daemon, S3): open the canonical
    /// namespaces from a read txn, never create. The read-only path serves
    /// lock checks only, so a missing DBI other than "locks" (a store
    /// provisioned by an older version or another daemon) is skipped with a
    /// warning; a missing "locks" DBI fails the open (S3 N8).
    fn openCanonicalNamespacesReadOnly(self: *LmdbBackend) !void {
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadOnly });
        errdefer txn.abort();
        for (backend.canonical_namespaces) |ns| {
            var name_z: [65]u8 = undefined;
            if (ns.len > 64) return error.MDB_BAD_VALSIZE;
            @memcpy(name_z[0..ns.len], ns);
            name_z[ns.len] = 0;
            const db = lmdb.Database.open(txn, @ptrCast(name_z[0..ns.len :0]), .{}) catch |err| {
                if (std.mem.eql(u8, ns, "locks")) return err;
                log.warn("read-only open: namespace '{s}' missing; skipping", .{ns});
                continue;
            };
            const entry = &self.dbi_cache[self.dbi_count.load(.monotonic)];
            @memcpy(entry.name_buf[0..ns.len], ns);
            entry.name_len = @intCast(ns.len);
            entry.dbi = db.dbi;
            self.dbi_count.store(self.dbi_count.load(.monotonic) + 1, .release);
        }
        // Commit (not abort): handles opened in an aborted read txn are not
        // usable in later read txns on this LMDB (get() returned EINVAL).
        try txn.commit();
    }

    pub fn close(self: *LmdbBackend) void {
        // env.deinit() closes LMDB's descriptor first. Closing our held
        // descriptor after it is safe; doing so before would drop LMDB's
        // locks (D5).
        self.env.deinit();
        if (self.lock_file) |file| {
            file.close();
            self.lock_file = null;
        }
    }

    pub fn get(self: *LmdbBackend, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadOnly });
        defer txn.abort();

        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        const value = db.get(key) catch |err| {
            if (err == error.MDB_NOTFOUND) return null;
            return err;
        };
        const v = value orelse return null;
        return try allocator.dupe(u8, v);
    }

    pub fn put(self: *LmdbBackend, ns: []const u8, key: []const u8, value: []const u8) !void {
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        db.set(key, value) catch |err| {
            txn.abort();
            return err;
        };
        // commit() needs no error-guard: on failure mdb_txn_commit aborts
        // the txn internally (S9).
        try txn.commit();
        self.warnIfNearlyFull();
    }

    /// Log once when live content crosses 80% of the map; a full map is an
    /// operational error (restart with a bigger [server] lmdb_map_size_mb
    /// rather than resized at runtime, which LMDB forbids with open read
    /// txns). Uses mdb_env_info me_last_pgno: mdb_env_stat covers MAIN_DBI
    /// only and reported 4 KiB used at MAP_FULL (S9).
    fn warnIfNearlyFull(self: *LmdbBackend) void {
        if (self.usage_warned.load(.acquire)) return;
        var info: MdbEnvInfoC = undefined;
        if (mdb_env_info(self.env.ptr, &info) != 0) return;
        const st = self.env.stat() catch return;
        const used_bytes: usize = @intCast((info.me_last_pgno + 1) * @as(usize, st.psize));
        if (used_bytes > self.map_size / 5 * 4) {
            self.usage_warned.store(true, .release);
            log.warn("LMDB map above 80 percent used ({d} of {d} bytes): raise [server] lmdb_map_size_mb and restart before MAP_FULL", .{ used_bytes, self.map_size });
        }
    }

    pub fn delete(self: *LmdbBackend, ns: []const u8, key: []const u8) !void {
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        db.delete(key) catch |err| {
            txn.abort();
            if (err == error.MDB_NOTFOUND) return;
            return err;
        };
        try txn.commit();
    }

    pub fn iterator(self: *LmdbBackend, ns: []const u8, prefix: []const u8) !Iterator {
        if (prefix.len > backend.MAX_PREFIX_LEN) return error.PrefixTooLong;
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadOnly });
        errdefer txn.abort();

        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        const cur = try db.cursor();

        var iter = Iterator{
            .cursor = cur,
            .txn = txn,
            .prefix = undefined,
            .prefix_len = prefix.len,
            .started = false,
        };
        @memcpy(iter.prefix[0..iter.prefix_len], prefix);
        return iter;
    }

    pub fn writeBatch(self: *LmdbBackend) !WriteBatch {
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        self.dbi_lock.lock();
        const dc = self.dbi_count.load(.acquire);
        self.dbi_lock.unlock();
        return .{ .txn = txn, .backend = self, .dbi_count_at_start = dc };
    }

    // -- Iterator --

    pub const Iterator = struct {
        cursor: lmdb.Cursor,
        txn: lmdb.Transaction,
        prefix: [backend.MAX_PREFIX_LEN]u8,
        prefix_len: usize,
        started: bool,

        pub fn next(self: *Iterator) ?backend.Entry {
            const key = if (!self.started) blk: {
                self.started = true;
                if (self.prefix_len == 0) {
                    break :blk self.cursor.goToFirst() catch return null;
                } else {
                    break :blk self.cursor.seek(self.prefix[0..self.prefix_len]) catch return null;
                }
            } else blk: {
                break :blk self.cursor.goToNext() catch return null;
            };

            const k = key orelse return null;
            if (!std.mem.startsWith(u8, k, self.prefix[0..self.prefix_len])) return null;

            const value = self.cursor.getCurrentValue() catch return null;
            return .{ .key = k, .value = value };
        }

        pub fn deinit(self: *Iterator) void {
            self.cursor.deinit();
            self.txn.abort();
        }
    };

    // -- WriteBatch --

    pub const WriteBatch = struct {
        txn: lmdb.Transaction,
        backend: *LmdbBackend,
        dbi_count_at_start: u32,
        ended: bool = false,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            const dbi = try self.resolveDbi(ns);
            const db = lmdb.Database{ .txn = self.txn, .dbi = dbi };
            try db.set(key, value);
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            const dbi = try self.resolveDbi(ns);
            const db = lmdb.Database{ .txn = self.txn, .dbi = dbi };
            db.delete(key) catch |err| {
                if (err == error.MDB_NOTFOUND) return;
                return err;
            };
        }

        pub fn commit(self: *WriteBatch) !void {
            // mdb_txn_commit ends the txn on failure as well (it aborts it
            // internally), so the batch is finished either way and abort()
            // must never end it again: a second mdb_txn_abort on the write
            // txn frees env->me_txn0 (S9).
            self.ended = true;
            self.txn.commit() catch |err| {
                self.rollbackDbiCache();
                return err;
            };
            // A batch can fill the map like any single put (S9).
            self.backend.warnIfNearlyFull();
        }

        pub fn abort(self: *WriteBatch) void {
            if (self.ended) return;
            self.ended = true;
            self.txn.abort();
            self.rollbackDbiCache();
        }

        /// Roll back DBI cache entries created during this batch: handles
        /// opened in a txn that never committed are not usable later.
        fn rollbackDbiCache(self: *WriteBatch) void {
            self.backend.dbi_lock.lock();
            self.backend.dbi_count.store(self.dbi_count_at_start, .release);
            self.backend.dbi_lock.unlock();
        }

        fn resolveDbi(self: *WriteBatch, ns: []const u8) !lmdb.Database.DBI {
            self.backend.dbi_lock.lock();
            defer self.backend.dbi_lock.unlock();
            const dc_n = self.backend.dbi_count.load(.acquire);
            for (self.backend.dbi_cache[0..dc_n]) |entry| {
                if (std.mem.eql(u8, entry.name_buf[0..entry.name_len], ns))
                    return entry.dbi;
            }
            var name_z: [65]u8 = undefined;
            if (ns.len > 64) return error.MDB_BAD_VALSIZE;
            @memcpy(name_z[0..ns.len], ns);
            name_z[ns.len] = 0;
            const db = try lmdb.Database.open(
                self.txn,
                @ptrCast(name_z[0..ns.len :0]),
                .{ .create = true },
            );
            const dc2 = self.backend.dbi_count.load(.acquire);
            if (dc2 < MAX_DBS) {
                var e = &self.backend.dbi_cache[dc2];
                @memcpy(e.name_buf[0..ns.len], ns);
                e.name_len = @intCast(ns.len);
                e.dbi = db.dbi;
                self.backend.dbi_count.store(dc2 + 1, .release);
            }
            return db.dbi;
        }
    };

    // -- Internal --

    fn findDbi(self: *LmdbBackend, ns: []const u8) ?lmdb.Database.DBI {
        // Canonical prefixes never move after open(); readers go lock-free
        // on an acquire-counted cache (S9).
        const n = self.dbi_count.load(.acquire);
        for (self.dbi_cache[0..n]) |entry| {
            if (std.mem.eql(u8, entry.name_buf[0..entry.name_len], ns))
                return entry.dbi;
        }
        return null;
    }

    fn getOrCreateDbi(self: *LmdbBackend, ns: []const u8) !lmdb.Database.DBI {
        if (self.findDbi(ns)) |d| return d;

        // A new namespace is test-only beyond the canonical set. The write
        // txn must not begin while holding dbi_lock (S9: a WriteBatch
        // holder waits for dbi_lock here while the txn begin waits on the
        // LMDB writer lock = deadlock window).
        var name_z: [65]u8 = undefined;
        if (ns.len > 64) return error.MDB_BAD_VALSIZE;
        @memcpy(name_z[0..ns.len], ns);
        name_z[ns.len] = 0;

        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        const db = lmdb.Database.open(
            txn,
            @ptrCast(name_z[0..ns.len :0]),
            .{ .create = true },
        ) catch |err| {
            txn.abort();
            return err;
        };
        // mdb_txn_commit aborts on failure internally; the write txn is
        // dead after this either way (S9).
        try txn.commit();

        self.dbi_lock.lock();
        defer self.dbi_lock.unlock();
        // Another creator may have raced in while the txn ran.
        if (self.findDbi(ns)) |d| return d;
        const n = self.dbi_count.load(.acquire);
        if (n >= MAX_DBS) return error.MDB_DBS_FULL;

        var entry = &self.dbi_cache[n];
        @memcpy(entry.name_buf[0..ns.len], ns);
        entry.name_len = @intCast(ns.len);
        entry.dbi = db.dbi;
        self.dbi_count.store(n + 1, .release);

        return db.dbi;
    }
};

// ============================================================================
// Tests
// ============================================================================

fn freshTestDir() []const u8 {
    const path = "/tmp/xmppd-test-lmdb";
    std.fs.cwd().deleteTree(path) catch {};
    return path;
}

test "LmdbBackend: open and close" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    db.close();
}

test "LmdbBackend: put and get" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds_alice");
    try db.put("users", "bob", "creds_bob");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("creds_alice", val.?);

    const missing = try db.get(std.testing.allocator, "users", "charlie");
    try std.testing.expect(missing == null);
}

test "LmdbBackend: delete" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds");
    try db.delete("users", "alice");

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);

    try db.delete("users", "nonexistent");
}

test "LmdbBackend: overwrite value" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "old");
    try db.put("users", "alice", "new");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("new", val.?);
}

test "LmdbBackend: separate namespaces" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "user_data");
    try db.put("rosters", "alice", "roster_data");

    const u = try db.get(std.testing.allocator, "users", "alice");
    defer if (u) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("user_data", u.?);

    const r = try db.get(std.testing.allocator, "rosters", "alice");
    defer if (r) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("roster_data", r.?);
}

test "LmdbBackend: iterator prefix-bounded" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("rosters", "alice\x00bob", "both");
    try db.put("rosters", "alice\x00carol", "to");
    try db.put("rosters", "bob\x00alice", "both");

    var iter = try db.iterator("rosters", "alice\x00");
    defer iter.deinit();

    var count: usize = 0;
    while (iter.next()) |entry| {
        try std.testing.expect(std.mem.startsWith(u8, entry.key, "alice\x00"));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "LmdbBackend: iterator honors a prefix past 256 bytes and rejects over-cap" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    // Two owners whose scan prefixes share the first 290 bytes: any
    // fixed-size clip shorter than the prefix merges their rows.
    const owner_a = ("a" ** 290) ++ "-first";
    const owner_b = ("a" ** 290) ++ "-other";
    comptime std.debug.assert(std.mem.eql(u8, owner_a[0..290], owner_b[0..290]));

    const ns = comptime backend.registered("rosters");
    const key_a = owner_a ++ "\x00item1";
    const key_b = owner_b ++ "\x00item2";
    try db.put(ns, key_a, "a");
    try db.put(ns, key_b, "b");

    const prefix = owner_a ++ "\x00";

    // Collect-then-delete, the pattern removeAll/destroyRoom callers use.
    // The scan is scoped: the iterator's read txn must close before the
    // deletes open a write txn on this thread.
    var keys: [4][backend.MAX_PREFIX_LEN]u8 = undefined;
    var key_lens: [4]usize = undefined;
    var scanned: usize = 0;
    {
        var iter = try db.iterator(ns, prefix);
        defer iter.deinit();
        while (iter.next()) |entry| {
            if (scanned == keys.len) return error.TooManyEntries;
            @memcpy(keys[scanned][0..entry.key.len], entry.key);
            key_lens[scanned] = entry.key.len;
            scanned += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), scanned);
    try std.testing.expectEqualStrings(key_a, keys[0][0..key_lens[0]]);

    for (key_lens[0..scanned], 0..) |len, i| {
        try db.delete(ns, keys[i][0..len]);
    }
    const b_val = try db.get(std.testing.allocator, ns, key_b);
    defer if (b_val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("b", b_val.?);

    try std.testing.expectError(error.PrefixTooLong, db.iterator(ns, "x" ** (backend.MAX_PREFIX_LEN + 1)));
}

test "LmdbBackend: iterator returns key and value" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("data", "key1", "value1");

    var iter = try db.iterator("data", "key");
    defer iter.deinit();

    const entry = iter.next() orelse return error.ExpectedEntry;
    try std.testing.expectEqualStrings("key1", entry.key);
    try std.testing.expectEqualStrings("value1", entry.value);
}

test "LmdbBackend: writeBatch commit" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    try batch.put("users", "bob", "b");
    try batch.commit();

    const a = try db.get(std.testing.allocator, "users", "alice");
    defer if (a) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("a", a.?);

    const b = try db.get(std.testing.allocator, "users", "bob");
    defer if (b) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("b", b.?);
}

test "LmdbBackend: writeBatch abort" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    batch.abort();

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}

test "LmdbBackend: abort after commit does not end the txn again" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    // A namespace outside the canonical set: the put appends a DBI cache
    // entry whose lifetime the test can observe.
    var batch = try db.writeBatch();
    try batch.put("scratch", "alice", "a");
    const dc_committed = db.dbi_count.load(.acquire);
    try batch.commit();
    // The commit ended the txn (a failed commit would have aborted it
    // internally): abort() must be a no-op, not a second mdb_txn_abort
    // freeing env->me_txn0 nor a DBI cache rollback.
    batch.abort();

    try std.testing.expectEqual(dc_committed, db.dbi_count.load(.acquire));

    // The env must still accept and hold a write.
    var batch2 = try db.writeBatch();
    try batch2.put("scratch", "bob", "b");
    try batch2.commit();

    const val = try db.get(std.testing.allocator, "scratch", "bob");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("b", val.?);
}

test "LmdbBackend: MAP_FULL is a hard error: no runtime env resize (T358)" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{ .map_size = 128 * 1024 });
    defer db.close();

    var big: [16384]u8 = @splat('x');
    var key_buf: [32]u8 = undefined;
    var got_full = false;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const key = std.fmt.bufPrint(&key_buf, "k{d}", .{i}) catch unreachable;
        db.put("users", key, &big) catch |err| {
            if (err == error.MDB_MAP_FULL) {
                got_full = true;
                break;
            }
            return err;
        };
    }
    try std.testing.expect(got_full);
    // The map size is untouched: nothing resized underneath readers.
    try std.testing.expectEqual(@as(usize, 128 * 1024), db.map_size);
}

test "LmdbBackend: a commit that hits the map limit ends the batch and rolls back the DBI cache" {
    const path = freshTestDir();
    // A small map is the fault hook (S9): at the map boundary a put can
    // succeed from the dirty page cache while the commit cannot allocate
    // the pages to write the batch out (MDB_MAP_FULL).
    var db = try LmdbBackend.open(path, .{ .map_size = 128 * 1024 });
    defer db.close();

    // Fill until a write fails: the map is at its limit and the map
    // boundary is exactly where a put fits but its commit does not.
    var big: [3000]u8 = @splat('x');
    var kbuf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const k = std.fmt.bufPrint(&kbuf, "k{d:0>4}", .{i}) catch unreachable;
        db.put("scratch", k, &big) catch break;
    }

    const dc0 = db.dbi_count.load(.acquire);
    var batch = try db.writeBatch();
    try batch.put("fresh", "a", "1");
    try batch.put("scratch", "b", "2");
    try std.testing.expectEqual(dc0 + 1, db.dbi_count.load(.acquire));
    try std.testing.expectError(error.MDB_MAP_FULL, batch.commit());

    // The batch is ended before the txn ran: abort() after the commit
    // attempt is a no-op (S9).
    try std.testing.expect(batch.ended);
    // The DBI opened inside the failed txn is not usable later.
    try std.testing.expectEqual(dc0, db.dbi_count.load(.acquire));
    batch.abort();
    try std.testing.expectEqual(dc0, db.dbi_count.load(.acquire));
}

test "LmdbBackend: read-only open with create=false serves reads, refuses to write" {
    const path = freshTestDir();
    // Seed with a writer open
    {
        var w = try LmdbBackend.open(path, .{});
        try w.put("locks", "alice", "locked");
        w.close();
    }

    var db = try LmdbBackend.open(path, .{ .create = false, .read_only = true });
    defer db.close();

    const val = try db.get(std.testing.allocator, "locks", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("locked", val.?);

    // Read-only mode: a write attempt must fail before hitting LMDB's
    // env, or the LMDB layer must report EACCES (exact error differs).
    if (db.put("locks", "bob", "x")) |_| {
        return error.ShouldHaveFailed;
    } else |_| {}
}

test "LmdbBackend: batch commit checks map usage and warns once" {
    const allocator = std.testing.allocator;
    const path = freshTestDir();
    std.fs.cwd().makePath(path) catch {};
    var db = try LmdbBackend.open(path, .{ .map_size = 512 * 1024 });
    defer db.close();
    try std.testing.expect(!db.usage_warned.load(.acquire));

    var batch = try db.writeBatch();
    // 3800-byte values keep each entry inside one 4 KiB page: 110 pages is
    // ~88 percent of the 512 KiB map, over the warning line and well under
    // MAP_FULL.
    const chunk = try allocator.alloc(u8, 3800);
    defer allocator.free(chunk);
    @memset(chunk, 'x');
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 110) : (i += 1) {
        const k = std.fmt.bufPrint(&kbuf, "key-{d}", .{i}) catch unreachable;
        try batch.put("messages", k, chunk);
    }
    try batch.commit();
    // The warning must come from the batch commit path (S9: it only
    // ran on single puts before).
    try std.testing.expect(db.usage_warned.load(.acquire));
}

test "LmdbBackend: read-only open needs only the locks namespace" {
    const allocator = std.testing.allocator;

    // Env provisioned with ONLY the "locks" DBI (a store written by an
    // older or foreign daemon): the read-only open must succeed.
    const path = freshTestDir();
    std.fs.cwd().makePath(path) catch {};
    {
        var path_buf: [256:0]u8 = undefined;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        const env = try lmdb.Environment.init(&path_buf, .{ .map_size = 1024 * 1024, .max_dbs = MAX_DBS });
        defer env.deinit();
        const txn = try lmdb.Transaction.init(env, .{ .mode = .ReadWrite });
        var db = try lmdb.Database.open(txn, "locks", .{ .create = true });
        try db.set("alice", "locked");
        try txn.commit();
    }
    var ro = try LmdbBackend.open(path, .{ .create = false, .read_only = true });
    defer ro.close();
    const v = try ro.get(allocator, "locks", "alice");
    defer if (v) |x| allocator.free(x);
    try std.testing.expect(v != null);

    // An env WITHOUT the locks DBI still fails the read-only open: the
    // daemon must not boot into fail-open on a store it cannot read.
    const path2 = "/tmp/xmppd-test-lmdb-n8b";
    std.fs.cwd().deleteTree(path2) catch {};
    defer std.fs.cwd().deleteTree(path2) catch {};
    try std.fs.cwd().makePath(path2);
    {
        var path_buf: [256:0]u8 = undefined;
        @memcpy(path_buf[0..path2.len], path2);
        path_buf[path2.len] = 0;
        const env = try lmdb.Environment.init(&path_buf, .{ .map_size = 1024 * 1024, .max_dbs = MAX_DBS });
        defer env.deinit();
        const txn = try lmdb.Transaction.init(env, .{ .mode = .ReadWrite });
        try txn.commit();
    }
    if (LmdbBackend.open(path2, .{ .create = false, .read_only = true })) |opened| {
        var m = opened;
        m.close();
        return error.ShouldHaveFailed;
    } else |_| {}
}

/// Count the open file descriptors of this process: a failed
/// LmdbBackend.open that leaks its env keeps the data/lock fds open (D5).
fn countOpenFds() usize {
    var count: usize = 0;
    var fd: std.c.fd_t = 0;
    while (fd < 4096) : (fd += 1) {
        if (std.c.fcntl(fd, std.posix.F.GETFD, @as(c_int, 0)) < 0) continue;
        count += 1;
    }
    return count;
}

test "LmdbBackend: a failed read-only open closes the env it created (D5)" {
    // The env initializes, then the missing "locks" DBI fails the open
    // (S3 N8). The env must close before the error returns: the
    // provisioning pass that follows the failure would otherwise run a
    // second env on the same files while the first is still open, where
    // LMDB drops the process's lock-file locks.
    const path = "/tmp/xmppd-test-lmdb-d5";
    std.fs.cwd().deleteTree(path) catch {};
    defer std.fs.cwd().deleteTree(path) catch {};
    try std.fs.cwd().makePath(path);
    {
        var path_buf: [256:0]u8 = undefined;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        const env = try lmdb.Environment.init(&path_buf, .{ .map_size = 1024 * 1024, .max_dbs = MAX_DBS });
        defer env.deinit();
        const txn = try lmdb.Transaction.init(env, .{ .mode = .ReadWrite });
        try txn.commit();
    }

    const before = countOpenFds();
    if (LmdbBackend.open(path, .{ .create = false, .read_only = true })) |opened| {
        var m = opened;
        m.close();
        return error.ShouldHaveFailed;
    } else |_| {}
    try std.testing.expectEqual(before, countOpenFds());
}

test "LmdbBackend: open advises MADV_NOCORE over the env map" {
    // Goal: read-write and read-only opens both exclude exactly the env
    // map VMA from core dumps. Method: the test seam records the madvise
    // arguments; the advised range must have the me_mapsize length and
    // contain a value pointer LMDB returned from inside the map.
    const path = freshTestDir();
    var info: MdbEnvInfoC = undefined;
    const users_ns = comptime backend.registered("users");

    const calls0 = madviseCall.calls;
    {
        var db = try LmdbBackend.open(path, .{});
        defer db.close();
        try std.testing.expectEqual(calls0 + 1, madviseCall.calls);
        try std.testing.expectEqual(std.c.MADV.NOCORE, madviseCall.advice);
        try std.testing.expectEqual(@as(c_int, 0), mdb_env_info(db.env.ptr, &info));
        try std.testing.expectEqual(info.me_mapsize, madviseCall.len);

        try db.put(users_ns, "probe-key", "probe-value");
        var iter = try db.iterator(users_ns, "probe-key");
        defer iter.deinit();
        const p = @intFromPtr(iter.next().?.value.ptr);
        try std.testing.expect(p >= madviseCall.addr and p < madviseCall.addr + madviseCall.len);
    }

    const calls1 = madviseCall.calls;
    {
        var db = try LmdbBackend.open(path, .{ .create = false, .read_only = true });
        defer db.close();
        try std.testing.expectEqual(calls1 + 1, madviseCall.calls);
        try std.testing.expectEqual(std.c.MADV.NOCORE, madviseCall.advice);
        try std.testing.expectEqual(@as(c_int, 0), mdb_env_info(db.env.ptr, &info));
        try std.testing.expectEqual(info.me_mapsize, madviseCall.len);

        var iter = try db.iterator(users_ns, "probe-key");
        defer iter.deinit();
        const p = @intFromPtr(iter.next().?.value.ptr);
        try std.testing.expect(p >= madviseCall.addr and p < madviseCall.addr + madviseCall.len);
    }
}

test "LmdbBackend: a madvise failure does not fail the open" {
    // Goal: open() succeeds and the store still works when MADV_NOCORE
    // cannot be applied. Method: the test seam returns an error.
    const path = freshTestDir();
    madviseCall.result = -1;
    defer madviseCall.result = 0;

    const calls0 = madviseCall.calls;
    var db = try LmdbBackend.open(path, .{});
    try std.testing.expectEqual(calls0 + 1, madviseCall.calls);
    defer db.close();
    const users_ns = comptime backend.registered("users");
    try db.put(users_ns, "alice", "creds");
    const val = try db.get(std.testing.allocator, users_ns, "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("creds", val.?);
}

test "LmdbBackend: the env map VMA match requires inode and filesystem" {
    // Goal: a same-inode record on another filesystem is skipped, so the
    // advice can never land on an unrelated mapping (ZFS inode numbers
    // repeat across datasets). Method: a synthetic kern.proc.vmmap
    // buffer holding two vnode records that share an inode but differ
    // in kve_vn_fsid.
    var recs = [_]KinfoVmentry{ std.mem.zeroes(KinfoVmentry), std.mem.zeroes(KinfoVmentry) };
    recs[0].kve_structsize = @sizeOf(KinfoVmentry);
    recs[0].kve_type = KVME_TYPE_VNODE;
    recs[0].kve_start = 0x1000;
    recs[0].kve_end = 0x2000;
    recs[0].kve_vn_fileid = 4242;
    recs[0].kve_vn_fsid = 0xAAAA;
    recs[1] = recs[0];
    recs[1].kve_start = 0x3000;
    recs[1].kve_end = 0x9000;
    recs[1].kve_vn_fsid = 0xBBBB;
    const buf = std.mem.sliceAsBytes(&recs);

    const rec = findVmRecord(buf, 4242, 0xBBBB) orelse return error.VmRecordNotFound;
    try std.testing.expectEqual(@as(u64, 0x3000), rec.kve_start);
    try std.testing.expect(findVmRecord(buf, 4242, 0xAAAA) != null);
    try std.testing.expect(findVmRecord(buf, 4242, 0xCCCC) == null);
}

test "LmdbBackend: the vmmap lookup retries ENOMEM and re-queries the size" {
    // Goal: mappings added between the size query and the read do not lose
    // the VMA. Method: the seam fails one read with ENOMEM, then returns
    // one matching record.
    vmmapCall.reset();
    defer vmmapCall.reset();
    vmmapCall.stub = true;
    vmmapCall.read_fails = 1;

    var recs = [_]KinfoVmentry{std.mem.zeroes(KinfoVmentry)};
    recs[0].kve_structsize = @sizeOf(KinfoVmentry);
    recs[0].kve_type = KVME_TYPE_VNODE;
    recs[0].kve_start = 0x7000;
    recs[0].kve_end = 0x9000;
    recs[0].kve_vn_fileid = 4242;
    recs[0].kve_vn_fsid = 0xAAAA;
    vmmapCall.records = std.mem.sliceAsBytes(&recs);

    const rec = (try findVmEntry(4242, 0xAAAA)) orelse return error.VmEntryNotFound;
    try std.testing.expectEqual(@as(u64, 0x7000), rec.kve_start);
    try std.testing.expectEqual(@as(usize, 2), vmmapCall.size_calls);
    try std.testing.expectEqual(@as(usize, 2), vmmapCall.read_calls);
}

test "LmdbBackend: the vmmap ENOMEM retry is bounded" {
    // Goal: repeated ENOMEM does not loop forever. Method: the seam fails
    // every read and the lookup must stop at VMMAP_ATTEMPTS_MAX.
    vmmapCall.reset();
    defer vmmapCall.reset();
    vmmapCall.stub = true;
    vmmapCall.read_fails = VMMAP_ATTEMPTS_MAX;

    var recs = [_]KinfoVmentry{std.mem.zeroes(KinfoVmentry)};
    recs[0].kve_structsize = @sizeOf(KinfoVmentry);
    recs[0].kve_type = KVME_TYPE_VNODE;
    recs[0].kve_vn_fileid = 4242;
    recs[0].kve_vn_fsid = 0xAAAA;
    vmmapCall.records = std.mem.sliceAsBytes(&recs);

    try std.testing.expectError(error.AttemptsExhausted, findVmEntry(4242, 0xAAAA));
    try std.testing.expectEqual(@as(usize, VMMAP_ATTEMPTS_MAX), vmmapCall.size_calls);
    try std.testing.expectEqual(@as(usize, VMMAP_ATTEMPTS_MAX), vmmapCall.read_calls);
}

test "LmdbBackend: vmmap lookup exhaustion does not fail the open" {
    // Goal: a lookup that exhausts its ENOMEM retries warns and leaves
    // the map in core dumps; it is never a verdict against the open
    // itself. Method: the seam fails every read; the open must still
    // succeed and no madvise can be attempted without a record.
    const path = freshTestDir();
    vmmapCall.reset();
    defer vmmapCall.reset();
    vmmapCall.stub = true;
    vmmapCall.read_fails = VMMAP_ATTEMPTS_MAX;

    const calls0 = madviseCall.calls;
    const warns0 = warnCall.exhausted_calls;
    var db = try LmdbBackend.open(path, .{});
    defer db.close();
    try std.testing.expectEqual(calls0, madviseCall.calls);
    try std.testing.expectEqual(@as(usize, VMMAP_ATTEMPTS_MAX), vmmapCall.read_calls);
    try std.testing.expectEqual(warns0 + 1, warnCall.exhausted_calls);
}

test "LmdbBackend: vmmap exhaustion is reported, a miss returns null" {
    // Goal: the caller can tell a lookup that ran out of attempts from
    // one that found no matching VMA. Method: the seam fails every read
    // (error.AttemptsExhausted), then returns records that match nothing
    // (null).
    vmmapCall.reset();
    defer vmmapCall.reset();
    vmmapCall.stub = true;
    vmmapCall.read_fails = VMMAP_ATTEMPTS_MAX;

    var recs = [_]KinfoVmentry{std.mem.zeroes(KinfoVmentry)};
    recs[0].kve_structsize = @sizeOf(KinfoVmentry);
    recs[0].kve_type = KVME_TYPE_VNODE;
    recs[0].kve_vn_fileid = 4242;
    recs[0].kve_vn_fsid = 0xAAAA;
    vmmapCall.records = std.mem.sliceAsBytes(&recs);

    try std.testing.expectError(error.AttemptsExhausted, findVmEntry(4242, 0xAAAA));
    try std.testing.expect((try findVmEntry(4242, 0xCCCC)) == null);
}

test "LmdbBackend: the real madvise marks the env VMA nocore" {
    // Goal: the syscall path the seam bypasses works end to end: the
    // real madvise accepts MADV_NOCORE on the VMA the lookup returns
    // and the kernel records KVME_FLAG_NOCOREDUMP on it. Method: advise
    // over the found record's range, then re-read the record and check
    // the flag. An LMDB value pointer pins the VMA to the env map.
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();
    const users_ns = comptime backend.registered("users");

    var fd: c_int = 0;
    try std.testing.expectEqual(@as(c_int, 0), mdb_env_get_fd(db.env.ptr, &fd));
    const st = try std.posix.fstat(fd);
    const rec = (try findVmEntry(st.ino, st.dev)) orelse return error.VmEntryNotFound;
    const start: usize = @intCast(rec.kve_start);
    const len: usize = @intCast(rec.kve_end - rec.kve_start);

    try db.put(users_ns, "probe-key", "probe-value");
    var iter = try db.iterator(users_ns, "probe-key");
    defer iter.deinit();
    const p = @intFromPtr(iter.next().?.value.ptr);
    try std.testing.expect(p >= start and p < start + len);

    const addr: *align(std.heap.page_size_min) anyopaque = @ptrFromInt(start);
    try std.testing.expectEqual(@as(c_int, 0), std.c.madvise(addr, len, std.c.MADV.NOCORE));

    const after = (try findVmEntry(st.ino, st.dev)) orelse return error.VmEntryNotFound;
    try std.testing.expectEqual(rec.kve_start, after.kve_start);
    try std.testing.expect(after.kve_flags & KVME_FLAG_NOCOREDUMP != 0);
}

fn expectPrefixScan(db: anytype, ns: []const u8, prefix: []const u8, want: usize) !void {
    // The iterator holds this thread's read txn: it is opened, drained and
    // deinit'd inside the call so later puts can open a write txn.
    var iter = try db.iterator(ns, prefix);
    defer iter.deinit();
    var n: usize = 0;
    while (iter.next()) |e| {
        try std.testing.expect(std.mem.startsWith(u8, e.key, prefix));
        n += 1;
    }
    try std.testing.expectEqual(want, n);
}

test "LmdbBackend: iterator scan over 0xFF tails, empty prefix, a shared-head owner and the exact cap" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();
    const ns = comptime backend.registered("rosters");

    // Keys that stress the lexicographic edges of a prefix scan: trailing
    // 0xFF bytes, a key sitting on the computed upper bound, and all-0xFF
    // prefixes. The counts pin the sorted order the scan must honor.
    const ks = [_][]const u8{ "ab\xFE\xFF", "ab\xFF", "ab\xFF\x00x", "ab\xFF\xFF", "ac", "\xFF\xFE", "\xFF\xFF", "\xFF\xFF\x01" };
    for (ks) |k| try db.put(ns, k, "v");
    try expectPrefixScan(&db, ns, "ab\xFF", 3);
    try expectPrefixScan(&db, ns, "ab\xFE", 1);
    try expectPrefixScan(&db, ns, "\xFF\xFF", 2);
    try expectPrefixScan(&db, ns, "\xFF", 3);
    try expectPrefixScan(&db, ns, "", 8);

    // Two owners sharing a 296-byte head: a clipped seek or compare merges
    // their rows.
    const owner_a = ("a" ** 290) ++ "-first\x00";
    const owner_b = ("a" ** 290) ++ "-other\x00";
    try db.put(ns, owner_a ++ "i", "a");
    try db.put(ns, owner_b ++ "i", "b");
    try expectPrefixScan(&db, ns, owner_b, 1);
    try expectPrefixScan(&db, ns, owner_a, 1);

    // An exact-cap prefix must be accepted and matched, not rejected.
    const cap = "c" ** backend.MAX_PREFIX_LEN;
    try db.put(ns, cap, "c");
    try expectPrefixScan(&db, ns, cap, 1);
    try expectPrefixScan(&db, ns, cap[0 .. backend.MAX_PREFIX_LEN - 1], 1);
}
