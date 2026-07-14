const std = @import("std");

const Certificate = std.crypto.Certificate;
const tls = std.crypto.tls;

pub const max_handshake_bytes = 64 * 1024;
pub const max_chain_certificates = 16;
pub const max_san_entries = 16;
pub const max_san_summary_bytes = 512;

pub const Negotiated = struct {
    version: tls.ProtocolVersion,
    cipher_suite: tls.CipherSuite,
};

const max_server_name_bytes = 255;
const max_alpn_summary_bytes = 128;
// ponytail: one maximum TLS record; stream-decode only if real ClientHello corpora exceed this bound.
const max_hello_bytes = tls.max_ciphertext_len;
const max_hello_records = 16;

pub const ClientHello = struct {
    legacy_version: tls.ProtocolVersion,
    cipher_suite_count: usize,
    offers_tls_1_2: bool = false,
    offers_tls_1_3: bool = false,
    supported_versions_present: bool = false,
    server_name: [max_server_name_bytes]u8 = undefined,
    server_name_len: usize = 0,
    alpn_summary: [max_alpn_summary_bytes]u8 = undefined,
    alpn_summary_len: usize = 0,
    alpn_truncated: bool = false,

    pub fn serverName(self: *const ClientHello) []const u8 {
        return self.server_name[0..self.server_name_len];
    }

    pub fn alpnSummary(self: *const ClientHello) []const u8 {
        return self.alpn_summary[0..self.alpn_summary_len];
    }
};

pub const HelloParseResult = union(enum) {
    need_more,
    not_tls,
    unsupported,
    client: ClientHello,
    server: Negotiated,
};

pub const Validity = enum {
    valid,
    expired,
    not_yet_valid,
};

pub const Metadata = struct {
    common_name: [255]u8 = undefined,
    common_name_len: usize = 0,
    issuer_common_name: [255]u8 = undefined,
    issuer_common_name_len: usize = 0,
    subject_hash: [64]u8 = undefined,
    issuer_hash: [64]u8 = undefined,
    leaf_hash: [64]u8 = undefined,
    san_summary: [max_san_summary_bytes]u8 = undefined,
    san_summary_len: usize = 0,
    not_before: u64,
    not_after: u64,
    validity: Validity,
    chain_count: u16,

    pub fn commonName(metadata: *const Metadata) []const u8 {
        return metadata.common_name[0..metadata.common_name_len];
    }

    pub fn issuerCommonName(metadata: *const Metadata) []const u8 {
        return metadata.issuer_common_name[0..metadata.issuer_common_name_len];
    }

    pub fn sanSummary(metadata: *const Metadata) []const u8 {
        return metadata.san_summary[0..metadata.san_summary_len];
    }
};

pub const Trust = union(enum) {
    trusted,
    untrusted: anyerror,
};

pub const VerifiedMetadata = struct {
    metadata: Metadata,
    trust: Trust,
};

const Record = struct {
    content_type: u8,
    header: *const [5]u8,
    payload: []const u8,
};

const RecordIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    fn next(iterator: *RecordIterator) ?Record {
        return iterator.nextChecked() catch null;
    }

    fn nextChecked(iterator: *RecordIterator) !?Record {
        if (iterator.index == iterator.bytes.len) return null;
        if (iterator.bytes.len - iterator.index < 5) return error.TruncatedTlsRecord;
        const header = iterator.bytes[iterator.index..][0..5];
        const payload_len = std.mem.readInt(u16, header[3..5], .big);
        if (payload_len > tls.max_ciphertext_len) return error.InvalidTlsRecord;
        if (iterator.bytes.len - iterator.index - 5 < payload_len) return error.TruncatedTlsRecord;
        iterator.index += 5 + payload_len;
        return .{
            .content_type = header[0],
            .header = header,
            .payload = iterator.bytes[iterator.index - payload_len .. iterator.index],
        };
    }
};

pub fn parseNegotiated(raw_records: []const u8) !Negotiated {
    var handshake: [8192]u8 = undefined;
    var handshake_len: usize = 0;
    var records: RecordIterator = .{ .bytes = raw_records };
    while (records.next()) |record| {
        if (record.content_type == @intFromEnum(tls.ContentType.application_data)) break;
        if (record.content_type != @intFromEnum(tls.ContentType.handshake)) continue;
        const copy_len = @min(record.payload.len, handshake.len - handshake_len);
        try append(&handshake, &handshake_len, record.payload[0..copy_len]);
        if (try parseServerHello(handshake[0..handshake_len])) |negotiated| return negotiated;
        if (copy_len != record.payload.len) return error.ServerHelloTooLarge;
    }
    return error.ServerHelloNotFound;
}

pub fn parseHello(raw_records: []const u8) !HelloParseResult {
    if (raw_records.len == 0) return .need_more;
    switch (@as(tls.ContentType, @enumFromInt(raw_records[0]))) {
        .handshake, .change_cipher_spec, .alert, .application_data => {},
        else => return .not_tls,
    }

    var handshake: [max_hello_bytes]u8 = undefined;
    var handshake_len: usize = 0;
    var record_count: usize = 0;
    var records: RecordIterator = .{ .bytes = raw_records };
    while (true) {
        const record = records.nextChecked() catch |err| switch (err) {
            error.TruncatedTlsRecord => return .need_more,
            else => return err,
        } orelse return .need_more;
        record_count += 1;
        if (record_count > max_hello_records) return error.TooManyHelloRecords;
        const record_version = std.mem.readInt(u16, record.header[1..3], .big);
        if (record_version < @intFromEnum(tls.ProtocolVersion.tls_1_0) or
            record_version > @intFromEnum(tls.ProtocolVersion.tls_1_3)) return error.InvalidTlsRecord;
        if (record.content_type != @intFromEnum(tls.ContentType.handshake)) return .unsupported;
        append(&handshake, &handshake_len, record.payload) catch return error.HelloTooLarge;

        if (handshake_len < 4) {
            continue;
        }
        const message_len = readU24(handshake[1..4]);
        if (message_len > handshake.len - 4) return error.HelloTooLarge;
        if (handshake_len < 4 + message_len) {
            continue;
        }

        const message = handshake[0 .. 4 + message_len];
        return switch (@as(tls.HandshakeType, @enumFromInt(message[0]))) {
            .client_hello => .{ .client = try parseClientHello(message[4..]) },
            .server_hello => .{ .server = (try parseServerHello(message)).? },
            else => .unsupported,
        };
    }
}

fn parseClientHello(body: []const u8) !ClientHello {
    if (body.len < 2 + 32 + 1) return error.InvalidClientHello;
    const legacy_version: tls.ProtocolVersion = @enumFromInt(std.mem.readInt(u16, body[0..2], .big));
    var cursor: usize = 34;

    const session_id_len: usize = body[cursor];
    cursor += 1;
    if (session_id_len > 32 or session_id_len > body.len - cursor) return error.InvalidClientHello;
    cursor += session_id_len;

    if (body.len - cursor < 2) return error.InvalidClientHello;
    const cipher_suites_len: usize = std.mem.readInt(u16, body[cursor..][0..2], .big);
    cursor += 2;
    if (cipher_suites_len == 0 or cipher_suites_len % 2 != 0 or cipher_suites_len > body.len - cursor) {
        return error.InvalidClientHello;
    }
    cursor += cipher_suites_len;

    if (body.len - cursor < 1) return error.InvalidClientHello;
    const compression_methods_len: usize = body[cursor];
    cursor += 1;
    if (compression_methods_len == 0 or compression_methods_len > body.len - cursor) return error.InvalidClientHello;
    cursor += compression_methods_len;

    var hello = ClientHello{
        .legacy_version = legacy_version,
        .cipher_suite_count = cipher_suites_len / 2,
        .offers_tls_1_2 = legacy_version == .tls_1_2,
    };
    if (cursor == body.len) return hello;
    if (body.len - cursor < 2) return error.InvalidClientHello;
    const extensions_len: usize = std.mem.readInt(u16, body[cursor..][0..2], .big);
    cursor += 2;
    if (extensions_len != body.len - cursor) return error.InvalidClientHello;

    const extensions_end = cursor + extensions_len;
    var saw_server_name = false;
    var saw_alpn = false;
    while (cursor < extensions_end) {
        if (extensions_end - cursor < 4) return error.InvalidClientHello;
        const extension_type = std.mem.readInt(u16, body[cursor..][0..2], .big);
        const extension_len: usize = std.mem.readInt(u16, body[cursor + 2 ..][0..2], .big);
        cursor += 4;
        if (extension_len > extensions_end - cursor) return error.InvalidClientHello;
        const extension = body[cursor..][0..extension_len];
        switch (extension_type) {
            @intFromEnum(tls.ExtensionType.server_name) => {
                if (saw_server_name) return error.InvalidClientHello;
                saw_server_name = true;
                try parseServerName(extension, &hello);
            },
            @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation) => {
                if (saw_alpn) return error.InvalidClientHello;
                saw_alpn = true;
                try parseAlpn(extension, &hello);
            },
            @intFromEnum(tls.ExtensionType.supported_versions) => {
                if (hello.supported_versions_present) return error.InvalidClientHello;
                try parseSupportedVersions(extension, &hello);
            },
            else => {},
        }
        cursor += extension_len;
    }
    return hello;
}

fn parseServerName(extension: []const u8, hello: *ClientHello) !void {
    if (extension.len < 2) return error.InvalidClientHello;
    const list_len: usize = std.mem.readInt(u16, extension[0..2], .big);
    if (list_len != extension.len - 2) return error.InvalidClientHello;

    var cursor: usize = 2;
    while (cursor < extension.len) {
        if (extension.len - cursor < 3) return error.InvalidClientHello;
        const name_type = extension[cursor];
        const name_len: usize = std.mem.readInt(u16, extension[cursor + 1 ..][0..2], .big);
        cursor += 3;
        if (name_len > extension.len - cursor) return error.InvalidClientHello;
        const name = extension[cursor..][0..name_len];
        cursor += name_len;
        if (name_type != 0 or hello.server_name_len != 0) continue;
        if (name.len == 0 or name.len > hello.server_name.len or !isSafeServerName(name)) continue;
        @memcpy(hello.server_name[0..name.len], name);
        hello.server_name_len = name.len;
    }
}

fn parseAlpn(extension: []const u8, hello: *ClientHello) !void {
    if (extension.len < 2) return error.InvalidClientHello;
    const list_len: usize = std.mem.readInt(u16, extension[0..2], .big);
    if (list_len != extension.len - 2) return error.InvalidClientHello;

    var cursor: usize = 2;
    while (cursor < extension.len) {
        const protocol_len: usize = extension[cursor];
        cursor += 1;
        if (protocol_len == 0 or protocol_len > extension.len - cursor) return error.InvalidClientHello;
        const value = extension[cursor..][0..protocol_len];
        cursor += protocol_len;
        if (hello.alpn_summary_len != 0) {
            if (hello.alpn_summary.len - hello.alpn_summary_len < 2) {
                hello.alpn_truncated = true;
                continue;
            }
            hello.alpn_summary[hello.alpn_summary_len] = ',';
            hello.alpn_summary_len += 1;
        }
        for (value) |byte| {
            if (hello.alpn_summary_len == hello.alpn_summary.len) {
                hello.alpn_truncated = true;
                break;
            }
            hello.alpn_summary[hello.alpn_summary_len] = if (byte >= 0x21 and byte <= 0x7e and
                byte != ',' and byte != ';' and byte != '=' and byte != '\\') byte else '_';
            hello.alpn_summary_len += 1;
        }
    }
}

fn parseSupportedVersions(extension: []const u8, hello: *ClientHello) !void {
    if (extension.len < 1) return error.InvalidClientHello;
    const list_len: usize = extension[0];
    if (list_len == 0 or list_len % 2 != 0 or list_len != extension.len - 1) return error.InvalidClientHello;
    hello.supported_versions_present = true;
    hello.offers_tls_1_2 = false;
    hello.offers_tls_1_3 = false;
    var cursor: usize = 1;
    while (cursor < extension.len) : (cursor += 2) {
        switch (@as(tls.ProtocolVersion, @enumFromInt(std.mem.readInt(u16, extension[cursor..][0..2], .big)))) {
            .tls_1_2 => hello.offers_tls_1_2 = true,
            .tls_1_3 => hello.offers_tls_1_3 = true,
            else => {},
        }
    }
}

fn isSafeServerName(name: []const u8) bool {
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '-' and byte != '_') return false;
    }
    return true;
}

fn parseServerHello(handshake: []const u8) !?Negotiated {
    var index: usize = 0;
    while (handshake.len - index >= 4) {
        const message_len = readU24(handshake[index + 1 ..][0..3]);
        if (message_len > handshake.len - index - 4) return null;
        const body = handshake[index + 4 ..][0..message_len];
        index += 4 + message_len;
        if (handshake[index - message_len - 4] != @intFromEnum(tls.HandshakeType.server_hello)) continue;
        if (body.len < 2 + 32 + 1) return error.InvalidServerHello;
        const legacy_version: tls.ProtocolVersion = @enumFromInt(std.mem.readInt(u16, body[0..2], .big));
        const session_id_len = body[34];
        var cursor: usize = 35 + session_id_len;
        if (session_id_len > 32 or body.len -| cursor < 3) return error.InvalidServerHello;
        const cipher_suite: tls.CipherSuite = @enumFromInt(std.mem.readInt(u16, body[cursor..][0..2], .big));
        const compression_method = body[cursor + 2];
        cursor += 3;

        var version = legacy_version;
        var saw_supported_versions = false;
        if (body.len > cursor) {
            if (body.len - cursor < 2) return error.InvalidServerHello;
            const extensions_len = std.mem.readInt(u16, body[cursor..][0..2], .big);
            cursor += 2;
            if (extensions_len != body.len - cursor) return error.InvalidServerHello;
            const extensions_end = cursor + extensions_len;
            while (extensions_end - cursor >= 4) {
                const extension_type = std.mem.readInt(u16, body[cursor..][0..2], .big);
                const extension_len = std.mem.readInt(u16, body[cursor + 2 ..][0..2], .big);
                cursor += 4;
                if (extension_len > extensions_end - cursor) return error.InvalidServerHello;
                if (extension_type == @intFromEnum(tls.ExtensionType.supported_versions)) {
                    if (saw_supported_versions) return error.InvalidServerHello;
                    saw_supported_versions = true;
                    if (extension_len != 2) return error.InvalidServerHello;
                    version = @enumFromInt(std.mem.readInt(u16, body[cursor..][0..2], .big));
                }
                cursor += extension_len;
            }
            if (cursor != extensions_end) return error.InvalidServerHello;
        }
        if (version != .tls_1_2 and version != .tls_1_3) return error.UnsupportedTlsVersion;
        if (version == .tls_1_3 and compression_method != 0) return error.InvalidServerHello;
        return .{ .version = version, .cipher_suite = cipher_suite };
    }
    return null;
}

pub fn extract(
    raw_records: []const u8,
    key_log: []const u8,
    negotiated: Negotiated,
    now_seconds: i64,
) !Metadata {
    var plaintext: [max_handshake_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext);
    const chain = try decodeChain(raw_records, key_log, negotiated, &plaintext);
    return metadataFromChain(chain, now_seconds);
}

pub fn extractVerified(
    raw_records: []const u8,
    key_log: []const u8,
    negotiated: Negotiated,
    now_seconds: i64,
    bundle: *const Certificate.Bundle,
) !VerifiedMetadata {
    var plaintext: [max_handshake_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext);
    const chain = try decodeChain(raw_records, key_log, negotiated, &plaintext);
    const trust = classifyTrust(verifyChain(chain, bundle, now_seconds));
    return .{
        .metadata = try metadataFromChain(chain, now_seconds),
        .trust = trust,
    };
}

fn decodeChain(
    raw_records: []const u8,
    key_log: []const u8,
    negotiated: Negotiated,
    plaintext: *[max_handshake_bytes]u8,
) !Chain {
    const plaintext_len = switch (negotiated.version) {
        .tls_1_2 => try appendTls12Handshake(raw_records, plaintext),
        .tls_1_3 => try appendTls13Handshake(raw_records, key_log, negotiated.cipher_suite, plaintext),
        else => return error.UnsupportedTlsVersion,
    };
    return findCertificateChain(plaintext[0..plaintext_len], negotiated.version);
}

fn metadataFromChain(chain: Chain, now_seconds: i64) !Metadata {
    const parsed = try (Certificate{ .buffer = chain.leaf, .index = 0 }).parse();

    var metadata: Metadata = .{
        .not_before = parsed.validity.not_before,
        .not_after = parsed.validity.not_after,
        .validity = if (now_seconds < parsed.validity.not_before)
            .not_yet_valid
        else if (now_seconds > parsed.validity.not_after)
            .expired
        else
            .valid,
        .chain_count = chain.count,
    };
    metadata.common_name_len = copyDisplay(&metadata.common_name, parsed.commonName());
    metadata.issuer_common_name_len = copyDisplay(&metadata.issuer_common_name, findNameCommonName(parsed.issuer()) catch "");
    hashHex(parsed.subject(), &metadata.subject_hash);
    hashHex(parsed.issuer(), &metadata.issuer_hash);
    hashHex(chain.leaf, &metadata.leaf_hash);
    metadata.san_summary_len = try summarizeSan(parsed.subjectAltName(), &metadata.san_summary);
    return metadata;
}

fn appendTls12Handshake(raw_records: []const u8, output: *[max_handshake_bytes]u8) !usize {
    var written: usize = 0;
    var records: RecordIterator = .{ .bytes = raw_records };
    while (records.next()) |record| {
        if (record.content_type == @intFromEnum(tls.ContentType.change_cipher_spec)) break;
        if (record.content_type == @intFromEnum(tls.ContentType.handshake)) try append(output, &written, record.payload);
    }
    return written;
}

fn appendTls13Handshake(
    raw_records: []const u8,
    key_log: []const u8,
    cipher_suite: tls.CipherSuite,
    output: *[max_handshake_bytes]u8,
) !usize {
    return switch (cipher_suite) {
        .AES_128_GCM_SHA256 => decryptTls13(std.crypto.aead.aes_gcm.Aes128Gcm, std.crypto.hash.sha2.Sha256, raw_records, key_log, output),
        .AES_256_GCM_SHA384 => decryptTls13(std.crypto.aead.aes_gcm.Aes256Gcm, std.crypto.hash.sha2.Sha384, raw_records, key_log, output),
        .CHACHA20_POLY1305_SHA256 => decryptTls13(std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.sha2.Sha256, raw_records, key_log, output),
        .AEGIS_256_SHA512 => decryptTls13(std.crypto.aead.aegis.Aegis256, std.crypto.hash.sha2.Sha512, raw_records, key_log, output),
        .AEGIS_128L_SHA256 => decryptTls13(std.crypto.aead.aegis.Aegis128L, std.crypto.hash.sha2.Sha256, raw_records, key_log, output),
        else => error.UnsupportedTls13Cipher,
    };
}

fn decryptTls13(
    comptime Aead: type,
    comptime Hash: type,
    raw_records: []const u8,
    key_log: []const u8,
    output: *[max_handshake_bytes]u8,
) !usize {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
    var secret: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    try findHandshakeSecret(key_log, &secret);
    var key = tls.hkdfExpandLabel(Hkdf, secret, "key", "", Aead.key_length);
    defer std.crypto.secureZero(u8, &key);
    var iv = tls.hkdfExpandLabel(Hkdf, secret, "iv", "", Aead.nonce_length);
    defer std.crypto.secureZero(u8, &iv);

    var written: usize = 0;
    var sequence: u64 = 0;
    var records: RecordIterator = .{ .bytes = raw_records };
    while (records.next()) |record| {
        if (record.content_type != @intFromEnum(tls.ContentType.application_data)) continue;
        if (record.payload.len < Aead.tag_length) return error.InvalidEncryptedRecord;
        const ciphertext = record.payload[0 .. record.payload.len - Aead.tag_length];
        if (ciphertext.len > output.len - written) return error.HandshakeTooLarge;
        const cleartext = output[written..][0..ciphertext.len];
        const auth_tag = record.payload[record.payload.len - Aead.tag_length ..][0..Aead.tag_length];
        var nonce = iv;
        defer std.crypto.secureZero(u8, &nonce);
        var sequence_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequence_bytes, sequence, .big);
        for (sequence_bytes, nonce[nonce.len - 8 ..]) |byte, *nonce_byte| nonce_byte.* ^= byte;
        Aead.decrypt(cleartext, ciphertext, auth_tag.*, record.header, nonce, key) catch return error.TlsBadRecordMac;
        sequence += 1;

        const unpadded_len = std.mem.trimEnd(u8, cleartext, "\x00").len;
        if (unpadded_len == 0) return error.InvalidTlsInnerPlaintext;
        if (cleartext[unpadded_len - 1] == @intFromEnum(tls.ContentType.handshake)) {
            written += unpadded_len - 1;
            if (hasCompleteCertificateMessage(output[0..written])) break;
        }
    }
    return written;
}

const Chain = struct {
    leaf: []const u8,
    certificates: [max_chain_certificates][]const u8,
    count: u16,
};

const CertificateConstraints = struct {
    basic_constraints_present: bool = false,
    is_ca: bool = false,
    path_len: ?u32 = null,
    key_usage_present: bool = false,
    digital_signature: bool = false,
    key_cert_sign: bool = false,
    extended_key_usage_present: bool = false,
    server_auth: bool = false,
    name_constraints_present: bool = false,
};

const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_name_constraints = [_]u8{ 0x55, 0x1d, 0x1e };
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };
const oid_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25 };
const oid_server_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
const oid_any_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25, 0x00 };

fn findCertificateChain(handshake: []const u8, version: tls.ProtocolVersion) !Chain {
    var index: usize = 0;
    while (handshake.len - index >= 4) {
        const message_type = handshake[index];
        const message_len = readU24(handshake[index + 1 ..][0..3]);
        index += 4;
        if (message_len > handshake.len - index) return error.TruncatedHandshakeMessage;
        const body = handshake[index..][0..message_len];
        index += message_len;
        if (message_type != @intFromEnum(tls.HandshakeType.certificate)) continue;

        var cursor: usize = 0;
        if (version == .tls_1_3) {
            if (body.len < 1) return error.InvalidCertificateMessage;
            const context_len = body[0];
            cursor = 1 + context_len;
        }
        if (body.len -| cursor < 3) return error.InvalidCertificateMessage;
        const list_len = readU24(body[cursor..][0..3]);
        cursor += 3;
        if (list_len > body.len - cursor) return error.InvalidCertificateMessage;
        const list_end = cursor + list_len;
        var certificates: [max_chain_certificates][]const u8 = undefined;
        var count: usize = 0;
        while (cursor < list_end) {
            if (list_end - cursor < 3) return error.InvalidCertificateMessage;
            const certificate_len = readU24(body[cursor..][0..3]);
            cursor += 3;
            if (certificate_len > list_end - cursor) return error.InvalidCertificateMessage;
            if (count == max_chain_certificates) return error.TooManyCertificates;
            certificates[count] = body[cursor..][0..certificate_len];
            count += 1;
            cursor += certificate_len;
            if (version == .tls_1_3) {
                if (list_end - cursor < 2) return error.InvalidCertificateMessage;
                const extensions_len = std.mem.readInt(u16, body[cursor..][0..2], .big);
                cursor += 2;
                if (extensions_len > list_end - cursor) return error.InvalidCertificateMessage;
                cursor += extensions_len;
            }
        }
        if (count == 0) return error.EmptyCertificateChain;
        return .{
            .leaf = certificates[0],
            .certificates = certificates,
            .count = @intCast(count),
        };
    }
    return error.CertificateMessageNotFound;
}

fn verifyChain(chain: Chain, bundle: *const Certificate.Bundle, now_seconds: i64) !void {
    // ponytail: only the bounded server-supplied chain is used; add AIA fetching only if offline chain completion is required.
    const leaf_certificate: Certificate = .{ .buffer = chain.certificates[0], .index = 0 };
    const leaf_constraints = try parseCertificateConstraints(leaf_certificate);
    try validateTlsCertificatePurpose(leaf_constraints);
    var subject = try leaf_certificate.parse();
    var ca_below: u32 = 0;
    for (chain.certificates[1..chain.count]) |issuer_bytes| {
        if (try tryVerifyAgainstBundle(subject, bundle, now_seconds, ca_below)) return;
        const issuer_certificate: Certificate = .{ .buffer = issuer_bytes, .index = 0 };
        const constraints = try parseCertificateConstraints(issuer_certificate);
        try validateIssuerConstraints(constraints, ca_below);
        const issuer = try issuer_certificate.parse();
        try subject.verify(issuer, now_seconds);
        subject = issuer;
        ca_below += 1;
    }
    try verifyAgainstBundle(subject, bundle, now_seconds, ca_below);
}

fn tryVerifyAgainstBundle(
    subject: Certificate.Parsed,
    bundle: *const Certificate.Bundle,
    now_seconds: i64,
    ca_below: u32,
) !bool {
    verifyAgainstBundle(subject, bundle, now_seconds, ca_below) catch |err| switch (err) {
        error.CertificateIssuerNotFound => return false,
        else => return err,
    };
    return true;
}

fn verifyAgainstBundle(
    subject: Certificate.Parsed,
    bundle: *const Certificate.Bundle,
    now_seconds: i64,
    ca_below: u32,
) !void {
    const issuer_index = bundle.find(subject.issuer()) orelse return error.CertificateIssuerNotFound;
    const issuer_certificate: Certificate = .{ .buffer = bundle.bytes.items, .index = issuer_index };
    const constraints = try parseCertificateConstraints(issuer_certificate);
    try validateIssuerConstraints(constraints, ca_below);
    const issuer = try issuer_certificate.parse();
    try subject.verify(issuer, now_seconds);
}

fn validateIssuerConstraints(constraints: CertificateConstraints, ca_below: u32) !void {
    if (constraints.name_constraints_present) return error.UnsupportedNameConstraints;
    // ponytail: legacy/trust-anchor certificates without CA=true are rejected; add an explicit anchor policy only if compatibility requires it.
    if (!constraints.basic_constraints_present or !constraints.is_ca) return error.CertificateIssuerIsNotCa;
    if (constraints.key_usage_present and !constraints.key_cert_sign) {
        return error.CertificateIssuerCannotSignCertificates;
    }
    if (constraints.extended_key_usage_present and !constraints.server_auth) {
        return error.CertificateNotValidForTlsServer;
    }
    if (constraints.path_len) |path_len| {
        if (ca_below > path_len) return error.CertificatePathLengthExceeded;
    }
}

fn validateTlsCertificatePurpose(constraints: CertificateConstraints) !void {
    if (constraints.name_constraints_present) return error.UnsupportedNameConstraints;
    if (constraints.key_usage_present and !constraints.digital_signature) {
        return error.CertificateCannotAuthenticateTlsServer;
    }
    if (constraints.extended_key_usage_present and !constraints.server_auth) {
        return error.CertificateNotValidForTlsServer;
    }
}

fn parseCertificateConstraints(certificate: Certificate) !CertificateConstraints {
    const bytes = certificate.buffer;
    const outer = try parseDerElement(bytes, certificate.index);
    try expectDer(outer, .universal, .constructed, .sequence);
    const tbs = try parseDerChild(bytes, outer.slice.start, outer.slice.end);
    try expectDer(tbs, .universal, .constructed, .sequence);

    var cursor = tbs.slice.start;
    const first = try parseDerChild(bytes, cursor, tbs.slice.end);
    if (first.identifier.class == .context_specific and @intFromEnum(first.identifier.tag) == 0) {
        cursor = first.slice.end;
    }
    for (0..6) |_| {
        const field = try parseDerChild(bytes, cursor, tbs.slice.end);
        cursor = field.slice.end;
    }

    var constraints: CertificateConstraints = .{};
    var saw_extensions = false;
    while (cursor < tbs.slice.end) {
        const field = try parseDerChild(bytes, cursor, tbs.slice.end);
        cursor = field.slice.end;
        if (field.identifier.class != .context_specific) return error.InvalidCertificateExtensions;
        switch (@intFromEnum(field.identifier.tag)) {
            1, 2 => {},
            3 => {
                if (saw_extensions or field.identifier.pc != .constructed) return error.InvalidCertificateExtensions;
                saw_extensions = true;
                const extensions = try parseDerChild(bytes, field.slice.start, field.slice.end);
                try expectDer(extensions, .universal, .constructed, .sequence);
                if (extensions.slice.end != field.slice.end) return error.InvalidCertificateExtensions;
                try parseExtensions(bytes, extensions, &constraints);
            },
            else => return error.InvalidCertificateExtensions,
        }
    }
    return constraints;
}

fn parseExtensions(bytes: []const u8, extensions: Certificate.der.Element, constraints: *CertificateConstraints) !void {
    var cursor = extensions.slice.start;
    while (cursor < extensions.slice.end) {
        const extension = try parseDerChild(bytes, cursor, extensions.slice.end);
        cursor = extension.slice.end;
        try expectDer(extension, .universal, .constructed, .sequence);

        const oid = try parseDerChild(bytes, extension.slice.start, extension.slice.end);
        try expectDer(oid, .universal, .primitive, .object_identifier);
        var value_cursor = oid.slice.end;
        var critical = false;
        var value = try parseDerChild(bytes, value_cursor, extension.slice.end);
        if (value.identifier.class == .universal and value.identifier.tag == .boolean) {
            critical = try parseDerBoolean(bytes, value);
            value_cursor = value.slice.end;
            value = try parseDerChild(bytes, value_cursor, extension.slice.end);
        }
        try expectDer(value, .universal, .primitive, .octetstring);
        if (value.slice.end != extension.slice.end) return error.InvalidCertificateExtension;

        const oid_bytes = bytes[oid.slice.start..oid.slice.end];
        if (std.mem.eql(u8, oid_bytes, &oid_basic_constraints)) {
            if (constraints.basic_constraints_present) return error.DuplicateCertificateExtension;
            constraints.basic_constraints_present = true;
            const basic = try parseBasicConstraints(bytes, value);
            constraints.is_ca = basic.is_ca;
            constraints.path_len = basic.path_len;
        } else if (std.mem.eql(u8, oid_bytes, &oid_key_usage)) {
            if (constraints.key_usage_present) return error.DuplicateCertificateExtension;
            constraints.key_usage_present = true;
            const key_usage = try parseKeyUsage(bytes, value);
            constraints.digital_signature = key_usage.digital_signature;
            constraints.key_cert_sign = key_usage.key_cert_sign;
        } else if (std.mem.eql(u8, oid_bytes, &oid_extended_key_usage)) {
            if (constraints.extended_key_usage_present) return error.DuplicateCertificateExtension;
            constraints.extended_key_usage_present = true;
            constraints.server_auth = try parseExtendedKeyUsage(bytes, value);
        } else if (std.mem.eql(u8, oid_bytes, &oid_name_constraints)) {
            if (constraints.name_constraints_present) return error.DuplicateCertificateExtension;
            constraints.name_constraints_present = true;
        } else if (std.mem.eql(u8, oid_bytes, &oid_subject_alt_name)) {
            // Hostname matching and SAN DER parsing are performed separately by the TLS client and metadata extractor.
        } else if (critical) {
            return error.UnsupportedCriticalCertificateExtension;
        }
    }
}

fn parseBasicConstraints(bytes: []const u8, value: Certificate.der.Element) !struct { is_ca: bool, path_len: ?u32 } {
    const sequence = try parseDerChild(bytes, value.slice.start, value.slice.end);
    try expectDer(sequence, .universal, .constructed, .sequence);
    if (sequence.slice.end != value.slice.end) return error.InvalidBasicConstraints;

    var cursor = sequence.slice.start;
    var is_ca = false;
    var path_len: ?u32 = null;
    if (cursor < sequence.slice.end) {
        const first = try parseDerChild(bytes, cursor, sequence.slice.end);
        if (first.identifier.class == .universal and first.identifier.tag == .boolean) {
            is_ca = try parseDerBoolean(bytes, first);
            cursor = first.slice.end;
        }
    }
    if (cursor < sequence.slice.end) {
        const integer = try parseDerChild(bytes, cursor, sequence.slice.end);
        try expectDer(integer, .universal, .primitive, .integer);
        path_len = try parseNonNegativeInteger(bytes[integer.slice.start..integer.slice.end]);
        cursor = integer.slice.end;
    }
    if (cursor != sequence.slice.end or (path_len != null and !is_ca)) return error.InvalidBasicConstraints;
    return .{ .is_ca = is_ca, .path_len = path_len };
}

fn parseKeyUsage(bytes: []const u8, value: Certificate.der.Element) !struct { digital_signature: bool, key_cert_sign: bool } {
    const bit_string = try parseDerChild(bytes, value.slice.start, value.slice.end);
    try expectDer(bit_string, .universal, .primitive, .bitstring);
    if (bit_string.slice.end != value.slice.end) return error.InvalidKeyUsage;
    const content = bytes[bit_string.slice.start..bit_string.slice.end];
    if (content.len == 0 or content[0] > 7) return error.InvalidKeyUsage;
    if (content.len == 1 and content[0] != 0) return error.InvalidKeyUsage;
    if (content.len > 1 and content[0] != 0) {
        const mask = (@as(u8, 1) << @intCast(content[0])) - 1;
        if (content[content.len - 1] & mask != 0) return error.InvalidKeyUsage;
    }
    return .{
        .digital_signature = content.len > 1 and content[1] & 0x80 != 0,
        .key_cert_sign = content.len > 1 and content[1] & 0x04 != 0,
    };
}

fn parseExtendedKeyUsage(bytes: []const u8, value: Certificate.der.Element) !bool {
    const sequence = try parseDerChild(bytes, value.slice.start, value.slice.end);
    try expectDer(sequence, .universal, .constructed, .sequence);
    if (sequence.slice.end != value.slice.end or sequence.slice.start == sequence.slice.end) {
        return error.InvalidExtendedKeyUsage;
    }
    var cursor = sequence.slice.start;
    var server_auth = false;
    while (cursor < sequence.slice.end) {
        const oid = try parseDerChild(bytes, cursor, sequence.slice.end);
        cursor = oid.slice.end;
        try expectDer(oid, .universal, .primitive, .object_identifier);
        const oid_bytes = bytes[oid.slice.start..oid.slice.end];
        if (std.mem.eql(u8, oid_bytes, &oid_server_auth) or
            std.mem.eql(u8, oid_bytes, &oid_any_extended_key_usage)) server_auth = true;
    }
    return server_auth;
}

fn parseDerBoolean(bytes: []const u8, element: Certificate.der.Element) !bool {
    try expectDer(element, .universal, .primitive, .boolean);
    const content = bytes[element.slice.start..element.slice.end];
    if (content.len != 1 or (content[0] != 0 and content[0] != 0xff)) return error.InvalidDerBoolean;
    return content[0] == 0xff;
}

fn parseNonNegativeInteger(content: []const u8) !u32 {
    if (content.len == 0 or content[0] & 0x80 != 0) return error.InvalidDerInteger;
    var bytes = content;
    if (bytes.len > 1 and bytes[0] == 0) {
        if (bytes[1] & 0x80 == 0) return error.InvalidDerInteger;
        bytes = bytes[1..];
    }
    if (bytes.len > @sizeOf(u32)) return error.CertificatePathLengthTooLarge;
    var value: u32 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

fn parseDerChild(bytes: []const u8, index: u32, parent_end: u32) !Certificate.der.Element {
    if (index >= parent_end) return error.InvalidDerElement;
    const element = try parseDerElement(bytes, index);
    if (element.slice.end > parent_end) return error.InvalidDerElement;
    return element;
}

fn expectDer(
    element: Certificate.der.Element,
    class: Certificate.der.Class,
    pc: Certificate.der.PC,
    tag: Certificate.der.Tag,
) !void {
    if (element.identifier.class != class or element.identifier.pc != pc or element.identifier.tag != tag) {
        return error.InvalidDerElement;
    }
}

fn classifyTrust(verification: anyerror!void) Trust {
    verification catch |err| return .{ .untrusted = err };
    return .trusted;
}

fn hasCompleteCertificateMessage(handshake: []const u8) bool {
    var index: usize = 0;
    while (handshake.len - index >= 4) {
        const message_type = handshake[index];
        const message_len = readU24(handshake[index + 1 ..][0..3]);
        index += 4;
        if (message_len > handshake.len - index) return false;
        if (message_type == @intFromEnum(tls.HandshakeType.certificate)) return true;
        index += message_len;
    }
    return false;
}

fn findNameCommonName(name: []const u8) ![]const u8 {
    var name_index: u32 = 0;
    while (name_index < name.len) {
        const rdn = try parseDerElement(name, name_index);
        var rdn_index = rdn.slice.start;
        while (rdn_index < rdn.slice.end) {
            const attribute = try parseDerElement(name, rdn_index);
            const attribute_type = try parseDerElement(name, attribute.slice.start);
            const value = try parseDerElement(name, attribute_type.slice.end);
            if ((Certificate.parseAttribute(name, attribute_type) catch null) == .commonName) {
                return name[value.slice.start..value.slice.end];
            }
            rdn_index = attribute.slice.end;
        }
        name_index = rdn.slice.end;
    }
    return "";
}

fn summarizeSan(san: []const u8, output: *[max_san_summary_bytes]u8) !usize {
    if (san.len == 0) {
        @memcpy(output[0..4], "none");
        return 4;
    }
    const names = try parseDerElement(san, 0);
    var writer: std.Io.Writer = .fixed(output);
    var index = names.slice.start;
    var entries: usize = 0;
    var truncated = false;
    while (index < names.slice.end) {
        const name = try parseDerElement(san, index);
        index = name.slice.end;
        if (entries == max_san_entries) {
            truncated = true;
            continue;
        }
        const value = san[name.slice.start..name.slice.end];
        if (writer.end != 0) writer.writeAll(", ") catch {
            truncated = true;
            break;
        };
        const tag: Certificate.GeneralNameTag = @enumFromInt(@intFromEnum(name.identifier.tag));
        switch (tag) {
            .dNSName => {
                writer.writeAll("DNS:") catch return writer.end;
                var display: [255]u8 = undefined;
                const display_len = copyDisplay(&display, value);
                writer.writeAll(display[0..display_len]) catch {
                    truncated = true;
                    break;
                };
            },
            .iPAddress => switch (value.len) {
                4 => writer.print("IP:{d}.{d}.{d}.{d}", .{ value[0], value[1], value[2], value[3] }) catch {
                    truncated = true;
                    break;
                },
                16 => writer.print("IP6:{x}", .{value}) catch {
                    truncated = true;
                    break;
                },
                else => writer.writeAll("IP:invalid") catch {
                    truncated = true;
                    break;
                },
            },
            else => writer.print("other:{d}", .{@intFromEnum(tag)}) catch {
                truncated = true;
                break;
            },
        }
        entries += 1;
    }
    if (truncated and output.len - writer.end >= 5) writer.writeAll(" ...") catch {};
    return writer.end;
}

fn parseDerElement(bytes: []const u8, index: u32) !Certificate.der.Element {
    const start: usize = index;
    if (start >= bytes.len or bytes.len - start < 2) return error.InvalidDerElement;
    const size_byte = bytes[start + 1];
    var header_len: usize = 2;
    var content_len: usize = size_byte;
    if (size_byte & 0x80 != 0) {
        const length_bytes = size_byte & 0x7f;
        if (length_bytes == 0 or length_bytes > @sizeOf(u32) or bytes.len - start - 2 < length_bytes) {
            return error.InvalidDerElement;
        }
        header_len += length_bytes;
        content_len = 0;
        for (bytes[start + 2 ..][0..length_bytes]) |byte| content_len = (content_len << 8) | byte;
    }
    if (content_len > bytes.len - start - header_len) return error.InvalidDerElement;
    return Certificate.der.Element.parse(bytes, index);
}

fn findHandshakeSecret(key_log: []const u8, secret: []u8) !void {
    var lines = std.mem.splitScalar(u8, key_log, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ' ');
        const label = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const encoded = fields.next() orelse continue;
        if (!std.mem.eql(u8, label, "SERVER_HANDSHAKE_TRAFFIC_SECRET")) continue;
        if (encoded.len != secret.len * 2) return error.InvalidHandshakeSecret;
        _ = try std.fmt.hexToBytes(secret, encoded);
        return;
    }
    return error.HandshakeSecretNotFound;
}

fn hashHex(bytes: []const u8, output: *[64]u8) void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    _ = std.fmt.bufPrint(output, "{x}", .{digest}) catch unreachable;
}

fn copyDisplay(output: []u8, input: []const u8) usize {
    const source = input[0..@min(input.len, output.len)];
    if (std.unicode.utf8ValidateSlice(source)) {
        for (source, 0..) |byte, index| output[index] = if (byte < 0x20 or byte == 0x7f) '_' else byte;
        return source.len;
    }
    for (source, 0..) |byte, index| output[index] = if (byte >= 0x20 and byte <= 0x7e) byte else '_';
    return source.len;
}

fn append(output: []u8, written: *usize, bytes: []const u8) !void {
    if (bytes.len > output.len - written.*) return error.HandshakeTooLarge;
    @memcpy(output[written.*..][0..bytes.len], bytes);
    written.* += bytes.len;
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
}

fn makeClientHelloFixture(output: []u8) []u8 {
    var cursor: usize = 5;
    output[0..5].* = .{ @intFromEnum(tls.ContentType.handshake), 0x03, 0x03, 0, 0 };
    const handshake_start = cursor;
    output[cursor] = @intFromEnum(tls.HandshakeType.client_hello);
    cursor += 4;
    const body_start = cursor;
    appendTestBytes(output, &cursor, &.{ 0x03, 0x03 });
    @memset(output[cursor .. cursor + 32], 0x11);
    cursor += 32;
    appendTestBytes(output, &cursor, &.{0});
    appendTestU16(output, &cursor, 4);
    appendTestBytes(output, &cursor, &.{ 0x13, 0x01, 0xc0, 0x2f });
    appendTestBytes(output, &cursor, &.{ 1, 0 });
    const extensions_len_offset = cursor;
    cursor += 2;
    const extensions_start = cursor;

    appendTestU16(output, &cursor, @intFromEnum(tls.ExtensionType.server_name));
    appendTestU16(output, &cursor, 17);
    appendTestU16(output, &cursor, 15);
    appendTestBytes(output, &cursor, &.{0});
    appendTestU16(output, &cursor, 12);
    appendTestBytes(output, &cursor, "example.test");

    appendTestU16(output, &cursor, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
    appendTestU16(output, &cursor, 14);
    appendTestU16(output, &cursor, 12);
    appendTestBytes(output, &cursor, &.{2});
    appendTestBytes(output, &cursor, "h2");
    appendTestBytes(output, &cursor, &.{8});
    appendTestBytes(output, &cursor, "http/1.1");

    appendTestU16(output, &cursor, @intFromEnum(tls.ExtensionType.supported_versions));
    appendTestU16(output, &cursor, 5);
    appendTestBytes(output, &cursor, &.{ 4, 0x03, 0x04, 0x03, 0x03 });

    std.mem.writeInt(u16, output[extensions_len_offset..][0..2], @intCast(cursor - extensions_start), .big);
    writeTestU24(output[handshake_start + 1 ..][0..3], cursor - body_start);
    std.mem.writeInt(u16, output[3..5], @intCast(cursor - handshake_start), .big);
    return output[0..cursor];
}

fn makeServerHelloFixture(output: []u8) []u8 {
    var cursor: usize = 5;
    output[0..5].* = .{ @intFromEnum(tls.ContentType.handshake), 0x03, 0x03, 0, 0 };
    const handshake_start = cursor;
    output[cursor] = @intFromEnum(tls.HandshakeType.server_hello);
    cursor += 4;
    const body_start = cursor;
    appendTestBytes(output, &cursor, &.{ 0x03, 0x03 });
    @memset(output[cursor .. cursor + 32], 0x22);
    cursor += 32;
    appendTestBytes(output, &cursor, &.{ 0, 0x13, 0x01, 0 });
    appendTestU16(output, &cursor, 6);
    appendTestU16(output, &cursor, @intFromEnum(tls.ExtensionType.supported_versions));
    appendTestU16(output, &cursor, 2);
    appendTestBytes(output, &cursor, &.{ 0x03, 0x04 });
    writeTestU24(output[handshake_start + 1 ..][0..3], cursor - body_start);
    std.mem.writeInt(u16, output[3..5], @intCast(cursor - handshake_start), .big);
    return output[0..cursor];
}

fn appendTestBytes(output: []u8, cursor: *usize, bytes: []const u8) void {
    @memcpy(output[cursor.*..][0..bytes.len], bytes);
    cursor.* += bytes.len;
}

fn appendTestU16(output: []u8, cursor: *usize, value: u16) void {
    std.mem.writeInt(u16, output[cursor.*..][0..2], value, .big);
    cursor.* += 2;
}

fn writeTestU24(output: *[3]u8, value: usize) void {
    output.* = .{ @intCast(value >> 16), @intCast(value >> 8), @intCast(value) };
}

test "passive ClientHello exposes bounded SNI ALPN and offered versions" {
    var raw: [256]u8 = undefined;
    const parsed = try parseHello(makeClientHelloFixture(&raw));
    const hello = switch (parsed) {
        .client => |client| client,
        else => return error.ExpectedClientHello,
    };
    try std.testing.expectEqualStrings("example.test", hello.serverName());
    try std.testing.expectEqualStrings("h2,http/1.1", hello.alpnSummary());
    try std.testing.expectEqual(@as(usize, 2), hello.cipher_suite_count);
    try std.testing.expect(hello.offers_tls_1_2);
    try std.testing.expect(hello.offers_tls_1_3);
}

test "supported_versions overrides the TLS 1.3 legacy version" {
    const raw =
        "\x16\x03\x03\x00\x36" ++
        "\x01\x00\x00\x32\x03\x03" ++
        ("\x33" ** 32) ++
        "\x00\x00\x02\x13\x01\x01\x00\x00\x07\x00\x2b\x00\x03\x02\x03\x04";
    const parsed = try parseHello(raw);
    try std.testing.expect(parsed.client.offers_tls_1_3);
    try std.testing.expect(!parsed.client.offers_tls_1_2);
}

test "passive hello parsing waits across TLS records" {
    var raw: [256]u8 = undefined;
    const single = makeClientHelloFixture(&raw);
    const first_payload_len = 19;
    var fragmented: [300]u8 = undefined;
    fragmented[0..5].* = .{ @intFromEnum(tls.ContentType.handshake), 0x03, 0x03, 0, first_payload_len };
    @memcpy(fragmented[5 .. 5 + first_payload_len], single[5 .. 5 + first_payload_len]);
    const second = 5 + first_payload_len;
    fragmented[second .. second + 5].* = .{ @intFromEnum(tls.ContentType.handshake), 0x03, 0x03, 0, 0 };
    const remaining = single.len - 5 - first_payload_len;
    std.mem.writeInt(u16, fragmented[second + 3 ..][0..2], @intCast(remaining), .big);
    @memcpy(fragmented[second + 5 ..][0..remaining], single[5 + first_payload_len ..]);

    try std.testing.expectEqual(.need_more, try parseHello(fragmented[0 .. 5 + first_payload_len]));
    const parsed = try parseHello(fragmented[0 .. second + 5 + remaining]);
    try std.testing.expectEqualStrings("example.test", parsed.client.serverName());
}

test "passive ServerHello reuses negotiated version and cipher parsing" {
    var raw: [128]u8 = undefined;
    const parsed = try parseHello(makeServerHelloFixture(&raw));
    try std.testing.expectEqual(tls.ProtocolVersion.tls_1_3, parsed.server.version);
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, parsed.server.cipher_suite);
}

test "passive hello parser distinguishes incomplete non-TLS and malformed input" {
    try std.testing.expectEqual(.need_more, try parseHello("\x16\x03"));
    try std.testing.expectEqual(.not_tls, try parseHello("GET / HTTP/1.1\r\n"));
    try std.testing.expectEqual(.unsupported, try parseHello("\x17\x03\x03\x00\x01\x00"));
    try std.testing.expectError(error.InvalidClientHello, parseHello("\x16\x03\x03\x00\x05\x01\x00\x00\x01\x03"));
}

test "passive hello parser rejects ambiguous lengths and excessive records" {
    var client_raw: [256]u8 = undefined;
    const client = makeClientHelloFixture(&client_raw);
    client_raw[43] = 33;
    try std.testing.expectError(error.InvalidClientHello, parseHello(client));

    var server_raw: [128]u8 = undefined;
    const server = makeServerHelloFixture(&server_raw);
    server_raw[52] = 1;
    try std.testing.expectError(error.InvalidServerHello, parseHello(server));
    server_raw[52] = 2;
    server_raw[46] = 1;
    try std.testing.expectError(error.InvalidServerHello, parseHello(server));
    server_raw[46] = 0;
    server_raw[43] = 33;
    try std.testing.expectError(error.InvalidServerHello, parseHello(server));

    var empty_records: [5 * (max_hello_records + 1)]u8 = undefined;
    for (0..max_hello_records + 1) |index| {
        empty_records[index * 5 ..][0..5].* = .{ @intFromEnum(tls.ContentType.handshake), 0x03, 0x03, 0, 0 };
    }
    try std.testing.expectError(error.TooManyHelloRecords, parseHello(&empty_records));
}

const TestExtension = struct {
    oid: []const u8,
    critical: bool = false,
    value: []const u8,
};

fn buildConstraintTestCertificate(output: []u8, test_extensions: []const TestExtension) ![]const u8 {
    var extensions_content_buffer: [192]u8 = undefined;
    var extensions_content: std.Io.Writer = .fixed(&extensions_content_buffer);
    for (test_extensions) |test_extension| {
        var extension_buffer: [64]u8 = undefined;
        var extension: std.Io.Writer = .fixed(&extension_buffer);
        try writeShortDer(&extension, 0x06, test_extension.oid);
        if (test_extension.critical) try writeShortDer(&extension, 0x01, "\xff");
        try writeShortDer(&extension, 0x04, test_extension.value);
        try writeShortDer(&extensions_content, 0x30, extension.buffered());
    }

    var extensions_buffer: [200]u8 = undefined;
    var extensions: std.Io.Writer = .fixed(&extensions_buffer);
    try writeShortDer(&extensions, 0x30, extensions_content.buffered());

    var tbs_content_buffer: [240]u8 = undefined;
    var tbs_content: std.Io.Writer = .fixed(&tbs_content_buffer);
    try tbs_content.writeAll("\x02\x01\x01" ++ ("\x30\x00" ** 5));
    try writeShortDer(&tbs_content, 0xa3, extensions.buffered());

    var tbs_buffer: [248]u8 = undefined;
    var tbs: std.Io.Writer = .fixed(&tbs_buffer);
    try writeShortDer(&tbs, 0x30, tbs_content.buffered());

    var certificate_content_buffer: [252]u8 = undefined;
    var certificate_content: std.Io.Writer = .fixed(&certificate_content_buffer);
    try certificate_content.writeAll(tbs.buffered());
    var certificate: std.Io.Writer = .fixed(output);
    try writeShortDer(&certificate, 0x30, certificate_content.buffered());
    return certificate.buffered();
}

fn writeShortDer(writer: *std.Io.Writer, identifier: u8, content: []const u8) !void {
    if (content.len >= 128) return error.TestDerValueTooLong;
    try writer.writeByte(identifier);
    try writer.writeByte(@intCast(content.len));
    try writer.writeAll(content);
}

test "TLS 1.3 handshake records decrypt under key log secret" {
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const Hash = std.crypto.hash.sha2.Sha256;
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.Hmac(Hash));
    const secret = [_]u8{0x11} ** Hash.digest_length;
    const key = tls.hkdfExpandLabel(Hkdf, secret, "key", "", Aead.key_length);
    const iv = tls.hkdfExpandLabel(Hkdf, secret, "iv", "", Aead.nonce_length);
    const cleartext = [_]u8{ 11, 0, 0, 12, 0, 0, 0, 8, 0, 0, 3, 1, 2, 3, 0, 0, @intFromEnum(tls.ContentType.handshake) };
    var record: [5 + cleartext.len + Aead.tag_length]u8 = undefined;
    record[0] = @intFromEnum(tls.ContentType.application_data);
    record[1] = 3;
    record[2] = 3;
    std.mem.writeInt(u16, record[3..5], cleartext.len + Aead.tag_length, .big);
    Aead.encrypt(record[5..][0..cleartext.len], record[5 + cleartext.len ..], &cleartext, record[0..5], iv, key);

    var key_log_buffer: [256]u8 = undefined;
    const key_log = try std.fmt.bufPrint(&key_log_buffer, "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {x}\n", .{ "00" ** 32, secret });
    var decrypted: [max_handshake_bytes]u8 = undefined;
    const decrypted_len = try appendTls13Handshake(&record, key_log, .AES_128_GCM_SHA256, &decrypted);
    const chain = try findCertificateChain(decrypted[0..decrypted_len], .tls_1_3);
    try std.testing.expectEqual(@as(u16, 1), chain.count);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, chain.leaf);
}

test "issuer common name is read from a DER Name" {
    const name = "\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06issuer";
    try std.testing.expectEqualStrings("issuer", try findNameCommonName(name));
    try std.testing.expectError(error.InvalidDerElement, findNameCommonName("\x31"));
}

test "CA trust classification is deterministic without live roots" {
    const verified: anyerror!void = {};
    try std.testing.expect(classifyTrust(verified) == .trusted);
    switch (classifyTrust(error.CertificateIssuerNotFound)) {
        .untrusted => |err| try std.testing.expectEqual(error.CertificateIssuerNotFound, err),
        .trusted => return error.TestUnexpectedResult,
    }
}

test "issuer CA constraints fail closed" {
    const basic_ca = "\x30\x03\x01\x01\xff";
    const basic_not_ca = "\x30\x00";
    const basic_path_zero = "\x30\x06\x01\x01\xff\x02\x01\x00";
    const key_cert_sign = "\x03\x02\x02\x04";
    const digital_signature_only = "\x03\x02\x07\x80";

    var buffer: [256]u8 = undefined;
    const pseudo_ca = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_basic_constraints, .value = basic_not_ca },
        .{ .oid = &oid_key_usage, .value = key_cert_sign },
    });
    try std.testing.expectError(
        error.CertificateIssuerIsNotCa,
        validateIssuerConstraints(try parseCertificateConstraints(.{ .buffer = pseudo_ca, .index = 0 }), 0),
    );

    const missing_key_cert_sign = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_basic_constraints, .value = basic_ca },
        .{ .oid = &oid_key_usage, .value = digital_signature_only },
    });
    try std.testing.expectError(
        error.CertificateIssuerCannotSignCertificates,
        validateIssuerConstraints(try parseCertificateConstraints(.{ .buffer = missing_key_cert_sign, .index = 0 }), 0),
    );

    const no_key_usage = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_basic_constraints, .value = basic_ca },
    });
    try validateIssuerConstraints(try parseCertificateConstraints(.{ .buffer = no_key_usage, .index = 0 }), 0);

    const path_zero = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_basic_constraints, .value = basic_path_zero },
        .{ .oid = &oid_key_usage, .value = key_cert_sign },
    });
    const path_zero_constraints = try parseCertificateConstraints(.{ .buffer = path_zero, .index = 0 });
    try validateIssuerConstraints(path_zero_constraints, 0);
    try std.testing.expectError(error.CertificatePathLengthExceeded, validateIssuerConstraints(path_zero_constraints, 1));
}

test "unsupported certificate constraints and critical extensions fail closed" {
    var buffer: [256]u8 = undefined;
    const unknown_critical = try buildConstraintTestCertificate(&buffer, &.{.{
        .oid = &.{ 0x2a, 0x03, 0x04 },
        .critical = true,
        .value = "\x30\x00",
    }});
    try std.testing.expectError(
        error.UnsupportedCriticalCertificateExtension,
        parseCertificateConstraints(.{ .buffer = unknown_critical, .index = 0 }),
    );

    const name_constraints = try buildConstraintTestCertificate(&buffer, &.{.{
        .oid = &oid_name_constraints,
        .value = "\x30\x00",
    }});
    const parsed = try parseCertificateConstraints(.{ .buffer = name_constraints, .index = 0 });
    try std.testing.expectError(error.UnsupportedNameConstraints, validateIssuerConstraints(parsed, 0));
}

test "TLS leaf key usage and extended key usage are enforced" {
    const digital_signature = "\x03\x02\x07\x80";
    const key_cert_sign = "\x03\x02\x02\x04";
    const server_auth = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01";
    const client_auth = "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";

    var buffer: [256]u8 = undefined;
    const valid = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_key_usage, .value = digital_signature },
        .{ .oid = &oid_extended_key_usage, .value = server_auth },
    });
    try validateTlsCertificatePurpose(try parseCertificateConstraints(.{ .buffer = valid, .index = 0 }));

    const wrong_key_usage = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_key_usage, .value = key_cert_sign },
    });
    try std.testing.expectError(
        error.CertificateCannotAuthenticateTlsServer,
        validateTlsCertificatePurpose(try parseCertificateConstraints(.{ .buffer = wrong_key_usage, .index = 0 })),
    );

    const wrong_eku = try buildConstraintTestCertificate(&buffer, &.{
        .{ .oid = &oid_extended_key_usage, .value = client_auth },
    });
    try std.testing.expectError(
        error.CertificateNotValidForTlsServer,
        validateTlsCertificatePurpose(try parseCertificateConstraints(.{ .buffer = wrong_eku, .index = 0 })),
    );
}

test "SAN summary keeps DNS and IP entries within bounds" {
    const san = "\x30\x13\x82\x0bexample.com\x87\x04\xc0\x00\x02\x01";
    var summary_buffer: [max_san_summary_bytes]u8 = undefined;
    const summary_len = try summarizeSan(san, &summary_buffer);
    try std.testing.expectEqualStrings("DNS:example.com, IP:192.0.2.1", summary_buffer[0..summary_len]);

    var many_san: [2 + 17 * 3]u8 = undefined;
    many_san[0] = 0x30;
    many_san[1] = 17 * 3;
    for (0..17) |index| {
        const offset = 2 + index * 3;
        many_san[offset..][0..3].* = .{ 0x82, 1, 'a' };
    }
    const bounded_len = try summarizeSan(&many_san, &summary_buffer);
    try std.testing.expectEqual(@as(usize, max_san_entries), std.mem.count(u8, summary_buffer[0..bounded_len], "DNS:a"));
    try std.testing.expect(bounded_len <= max_san_summary_bytes);
    try std.testing.expect(std.mem.endsWith(u8, summary_buffer[0..bounded_len], " ..."));
}
