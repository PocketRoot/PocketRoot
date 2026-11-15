const std = @import("std");

pub const max_subject_bytes = 128;
pub const max_payload_bytes = 1024 * 1024;
pub const max_audit_entries = 4096;

pub const Kind = enum {
    subghz,
    nfc,
    lfrfid,
    infrared,
    ibutton,
    usb,
    ble,
    gpio,
    wifi,
    network,
    storage,
    system,
    // Reverse-engineering surface (appended so existing values stay stable).
    // usb_host is deliberately distinct from usb: usb means "we enumerate as a
    // device" (BadUSB), usb_host means "we enumerate the target".
    uart,
    spi,
    i2c,
    jtag,
    swd,
    logic,
    power,
    usb_host,
};

pub const Operation = enum {
    observe,
    read,
    capture,
    analyze,
    write,
    transmit,
    emulate,
    configure,
    manage,

    pub fn isActive(self: Operation) bool {
        return switch (self) {
            .write, .transmit, .emulate, .configure, .manage => true,
            else => false,
        };
    }
};

pub const Request = struct {
    id: u64,
    subject: []const u8,
    kind: Kind,
    operation: Operation,
    region: []const u8 = "",
    payload: []const u8 = "",
    active_authorized: bool = false,
};

pub const Status = enum {
    succeeded,
    unsupported,
    cancelled,
    failed,
    denied,
    busy,
};

pub const Result = struct {
    allocator: std.mem.Allocator,
    status: Status,
    data: []u8,

    pub fn init(allocator: std.mem.Allocator, status: Status, data: []const u8) !Result {
        return .{
            .allocator = allocator,
            .status = status,
            .data = try allocator.dupe(u8, data),
        };
    }

    pub fn deinit(self: *Result) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
};

pub const Policy = struct {
    region: []const u8 = "",
    allow_active: bool = false,
    stopped: bool = false,

    pub fn authorize(self: Policy, request: Request) !void {
        if (self.stopped) return error.EmergencyStopped;
        if (request.subject.len == 0) return error.MissingSubject;
        if (request.subject.len > max_subject_bytes) return error.SubjectTooLong;
        if (request.payload.len > max_payload_bytes) return error.PayloadTooLarge;

        if (request.operation.isActive()) {
            if (!self.allow_active or !request.active_authorized) return error.ActiveOperationDenied;
            if (request.kind == .subghz) {
                if (self.region.len == 0 or request.region.len == 0) return error.RegionRequired;
                if (!std.mem.eql(u8, self.region, request.region)) return error.RegionMismatch;
            }
        }
    }
};

pub const AuditEntry = struct {
    allocator: std.mem.Allocator,
    request_id: u64,
    subject: []u8,
    /// Recorded so an export can show why an active request was allowed or refused.
    region: []u8,
    active_authorized: bool,
    kind: Kind,
    operation: Operation,
    status: Status,

    fn init(allocator: std.mem.Allocator, request: Request, status: Status) !AuditEntry {
        const subject = try allocator.dupe(u8, request.subject);
        errdefer allocator.free(subject);
        const region = try allocator.dupe(u8, request.region);
        errdefer allocator.free(region);
        return .{
            .allocator = allocator,
            .request_id = request.id,
            .subject = subject,
            .region = region,
            .active_authorized = request.active_authorized,
            .kind = request.kind,
            .operation = request.operation,
            .status = status,
        };
    }

    fn deinit(self: *AuditEntry) void {
        self.allocator.free(self.subject);
        self.allocator.free(self.region);
        self.* = undefined;
    }
};

pub const AuditLog = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(AuditEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator) AuditLog {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AuditLog) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
    }

    pub fn append(self: *AuditLog, request: Request, status: Status) !void {
        if (self.entries.items.len >= max_audit_entries) return error.AuditLogFull;
        var entry = try AuditEntry.init(self.allocator, request, status);
        errdefer entry.deinit();
        try self.entries.append(self.allocator, entry);
    }
};

pub const ResourceLocks = struct {
    owners: [std.meta.fields(Kind).len]?u64 = [_]?u64{null} ** std.meta.fields(Kind).len,

    pub fn acquire(self: *ResourceLocks, kind: Kind, request_id: u64) !void {
        const owner = &self.owners[@intFromEnum(kind)];
        if (owner.* != null) return error.CapabilityBusy;
        owner.* = request_id;
    }

    pub fn release(self: *ResourceLocks, kind: Kind, request_id: u64) void {
        const owner = &self.owners[@intFromEnum(kind)];
        if (owner.* == request_id) owner.* = null;
    }

    pub fn releaseAll(self: *ResourceLocks) void {
        self.owners = [_]?u64{null} ** std.meta.fields(Kind).len;
    }
};

pub const ExecuteFn = *const fn (
    context: *anyopaque,
    allocator: std.mem.Allocator,
    request: Request,
) anyerror!Result;

pub const Service = struct {
    allocator: std.mem.Allocator,
    policy: Policy,
    locks: ResourceLocks = .{},
    audit: AuditLog,
    context: *anyopaque,
    execute_fn: ExecuteFn,

    pub fn init(
        allocator: std.mem.Allocator,
        policy: Policy,
        context: *anyopaque,
        execute_fn: ExecuteFn,
    ) Service {
        return .{
            .allocator = allocator,
            .policy = policy,
            .audit = AuditLog.init(allocator),
            .context = context,
            .execute_fn = execute_fn,
        };
    }

    pub fn deinit(self: *Service) void {
        self.audit.deinit();
    }

    pub fn execute(self: *Service, request: Request) !Result {
        self.policy.authorize(request) catch |err| {
            try self.audit.append(request, .denied);
            return err;
        };

        self.locks.acquire(request.kind, request.id) catch |err| {
            try self.audit.append(request, .busy);
            return err;
        };
        defer self.locks.release(request.kind, request.id);

        var result = self.execute_fn(self.context, self.allocator, request) catch |err| {
            try self.audit.append(request, .failed);
            return err;
        };
        errdefer result.deinit();
        try self.audit.append(request, result.status);
        return result;
    }

    pub fn emergencyStop(self: *Service) void {
        self.policy.stopped = true;
        self.locks.releaseAll();
    }

    pub fn restart(self: *Service) void {
        self.policy.stopped = false;
    }
};

const TestBackend = struct {
    calls: usize = 0,

    fn execute(context: *anyopaque, allocator: std.mem.Allocator, request: Request) !Result {
        const self: *TestBackend = @ptrCast(@alignCast(context));
        self.calls += 1;
        return Result.init(allocator, .succeeded, request.payload);
    }
};

test "capability service authorizes passive work and audits it" {
    var backend = TestBackend{};
    var service = Service.init(std.testing.allocator, .{}, &backend, TestBackend.execute);
    defer service.deinit();

    var result = try service.execute(.{
        .id = 1,
        .subject = "test",
        .kind = .infrared,
        .operation = .read,
        .payload = "capture",
    });
    defer result.deinit();

    try std.testing.expectEqual(Status.succeeded, result.status);
    try std.testing.expectEqualStrings("capture", result.data);
    try std.testing.expectEqual(@as(usize, 1), backend.calls);
    try std.testing.expectEqual(Status.succeeded, service.audit.entries.items[0].status);
}

test "active operations require policy and request authorization" {
    var backend = TestBackend{};
    var service = Service.init(std.testing.allocator, .{ .allow_active = true }, &backend, TestBackend.execute);
    defer service.deinit();

    try std.testing.expectError(error.ActiveOperationDenied, service.execute(.{
        .id = 2,
        .subject = "test",
        .kind = .infrared,
        .operation = .transmit,
    }));
    try std.testing.expectEqual(Status.denied, service.audit.entries.items[0].status);
    try std.testing.expectEqual(@as(usize, 0), backend.calls);
}

test "subghz transmission enforces configured region" {
    var backend = TestBackend{};
    var service = Service.init(std.testing.allocator, .{
        .region = "EU",
        .allow_active = true,
    }, &backend, TestBackend.execute);
    defer service.deinit();

    try std.testing.expectError(error.RegionMismatch, service.execute(.{
        .id = 3,
        .subject = "test",
        .kind = .subghz,
        .operation = .transmit,
        .region = "US",
        .active_authorized = true,
    }));
}

test "emergency stop denies work and clears resource locks" {
    var backend = TestBackend{};
    var service = Service.init(std.testing.allocator, .{}, &backend, TestBackend.execute);
    defer service.deinit();

    try service.locks.acquire(.gpio, 99);
    service.emergencyStop();
    try std.testing.expectError(error.EmergencyStopped, service.execute(.{
        .id = 4,
        .subject = "test",
        .kind = .gpio,
        .operation = .read,
    }));
    service.restart();

    var result = try service.execute(.{
        .id = 5,
        .subject = "test",
        .kind = .gpio,
        .operation = .read,
    });
    result.deinit();
}
