//! Append-only audit export (pocketroot.audit.v1).
//!
//! The capability kernel keeps its audit in memory so a request can never run
//! unaudited. This module is the host-side sink: one JSON object per line, written
//! positionally so each accepted request is durable before the next one runs.

const std = @import("std");
const capability = @import("../core/capability.zig");

pub const schema = "pocketroot.audit.v1";
pub const max_file_bytes = 8 * 1024 * 1024;
pub const max_entries = capability.max_audit_entries;
pub const max_line_bytes = 2048;

fn writeText(json: *std.json.Stringify, value: []const u8) !void {
    // JSON text must be UTF-8. The host validates its subject and region before it
    // executes anything, so this is a defence against a future caller, not a path the
    // CLI can reach after a request has already run.
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidAuditText;
    try json.write(value);
}

pub const Writer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    entries: usize = 0,
    next_seq: u64 = 1,

    /// Opens (or creates) the log and appends after the existing bytes. The file is not
    /// truncated: a repeated run extends the same evidence trail.
    pub fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Writer {
        if (path.len == 0) return error.InvalidAuditPath;
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .read = true });
        errdefer file.close(io);
        const size = (try file.stat(io)).size;
        if (size > max_file_bytes) return error.AuditLogTooLarge;
        var entries: usize = 0;
        var last_seq: u64 = 0;
        if (size > 0) {
            const data = try allocator.alloc(u8, @intCast(size));
            defer allocator.free(data);
            if (try file.readPositionalAll(io, data, 0) != data.len) return error.AuditLogTruncated;
            var scratch = std.heap.ArenaAllocator.init(allocator);
            defer scratch.deinit();
            var lines = std.mem.splitScalar(u8, data, '\n');
            while (lines.next()) |raw| {
                const line = std.mem.trim(u8, raw, " \t\r");
                if (line.len == 0) continue;
                entries += 1;
                const parsed = std.json.parseFromSliceLeaky(Record, scratch.allocator(), line, .{
                    .ignore_unknown_fields = true,
                }) catch return error.InvalidAuditLine;
                if (parsed.seq > last_seq) last_seq = parsed.seq;
            }
        }
        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .offset = size,
            .entries = entries,
            .next_seq = last_seq + 1,
        };
    }

    pub fn close(self: *Writer) void {
        self.file.close(self.io);
        self.* = undefined;
    }

    /// Appends one entry durably. Returns before the caller runs the next request.
    pub fn append(self: *Writer, entry: capability.AuditEntry, at_unix: i64) !void {
        if (self.entries >= max_entries) return error.AuditLogFull;
        var buffer: [max_line_bytes]u8 = undefined;
        var output: std.Io.Writer = .fixed(&buffer);
        var json: std.json.Stringify = .{ .writer = &output };

        try json.beginObject();
        try json.objectField("schema");
        try json.write(schema);
        try json.objectField("seq");
        try json.write(self.next_seq);
        try json.objectField("request_id");
        try json.write(entry.request_id);
        try json.objectField("subject");
        try writeText(&json, entry.subject);
        try json.objectField("kind");
        try json.write(@tagName(entry.kind));
        try json.objectField("operation");
        try json.write(@tagName(entry.operation));
        try json.objectField("status");
        try json.write(@tagName(entry.status));
        try json.objectField("region");
        try writeText(&json, entry.region);
        try json.objectField("active_authorized");
        try json.write(entry.active_authorized);
        try json.objectField("at_unix");
        try json.write(at_unix);
        try json.endObject();
        try output.writeByte('\n');

        const bytes = output.buffered();
        if (self.offset + bytes.len > max_file_bytes) return error.AuditLogTooLarge;
        try self.file.writePositionalAll(self.io, bytes, self.offset);
        self.offset += bytes.len;
        self.entries += 1;
        self.next_seq += 1;
    }
};

pub const Record = struct {
    schema: []const u8 = schema,
    seq: u64 = 0,
    request_id: u64 = 0,
    subject: []const u8 = "",
    kind: []const u8 = "",
    operation: []const u8 = "",
    status: []const u8 = "",
    region: []const u8 = "",
    active_authorized: bool = false,
    at_unix: i64 = 0,
};

pub const Summary = struct {
    entries: usize = 0,
    succeeded: usize = 0,
    denied: usize = 0,
    failed: usize = 0,
    unsupported: usize = 0,
    cancelled: usize = 0,
    busy: usize = 0,
    active_authorized: usize = 0,
    first_seq: u64 = 0,
    last_seq: u64 = 0,
    last_at_unix: i64 = 0,

    pub fn count(self: *Summary, record: Record) void {
        self.entries += 1;
        const status = std.meta.stringToEnum(capability.Status, record.status) orelse {
            self.failed += 1;
            return;
        };
        switch (status) {
            .succeeded => self.succeeded += 1,
            .denied => self.denied += 1,
            .failed => self.failed += 1,
            .unsupported => self.unsupported += 1,
            .cancelled => self.cancelled += 1,
            .busy => self.busy += 1,
        }
        if (record.active_authorized) self.active_authorized += 1;
        if (self.first_seq == 0) self.first_seq = record.seq;
        self.last_seq = record.seq;
        if (record.at_unix != 0) self.last_at_unix = record.at_unix;
    }
};

/// Parses JSONL written by Writer. Every line must be a pocketroot.audit.v1 object;
/// a malformed line is an error rather than a skipped record, because this file is
/// evidence. Memory is owned by the caller's allocator.
pub fn parse(allocator: std.mem.Allocator, data: []const u8) ![]Record {
    if (data.len > max_file_bytes) return error.AuditLogTooLarge;
    var records: std.ArrayList(Record) = .empty;
    errdefer records.deinit(allocator);
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (line.len > max_line_bytes) return error.AuditLineTooLong;
        const parsed = std.json.parseFromSliceLeaky(Record, allocator, line, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidAuditLine;
        if (!std.mem.eql(u8, parsed.schema, schema)) return error.UnsupportedAuditSchema;
        if (records.items.len >= max_entries) return error.AuditLogFull;
        try records.append(allocator, parsed);
    }
    return records.toOwnedSlice(allocator);
}
