//! PocketRoot script DSL (pocketroot.script.v1) — stage S1.
//!
//! Scope: lexer, parser and validator only. Nothing here executes.
//! Syntax is Lua-like block form (do/end); indentation is never significant.
//! Strings are not escaped yet (S3); the whole source is owned by an arena.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const schema = "pocketroot.script.v1";

pub const max_script_bytes = 256 * 1024;
pub const max_uses = 16;
pub const max_caps = 128;
pub const max_steps = 256;
pub const max_statements_per_step = 512;
pub const max_options = 32;
pub const max_name_bytes = 128;
pub const max_text_bytes = 1024;
pub const max_time_ms = 10 * 60 * 1000;
pub const max_loop_count = 64;

pub const Error = error{
    OutOfMemory,
    EmptyScript,
    ScriptTooLarge,
    UnexpectedCharacter,
    UnterminatedString,
    UnexpectedToken,
    MissingEnd,
    MissingDo,
    InvalidScriptName,
    InvalidUse,
    TooManyItems,
    DuplicateCap,
    UnknownVerb,
    UndeclaredCap,
    DuplicateVariable,
    InvalidBudgetKey,
    DuplicateBudgetKey,
    InvalidDuration,
    InvalidSeverity,
    MissingSeverity,
    MissingMessage,
    UnknownOptionKey,
    TrailingInput,
    InvalidNumber,
    InvalidLoopBound,
    UnknownVariable,
    InvalidReference,
    InvalidOptionValue,
    UnknownPack,
    PackNotImported,
    UnknownScript,
    ScriptCycle,
    ScriptDepthExceeded,
};

pub const Diagnostic = struct {
    line: u32,
    message: []const u8,
};

pub const Severity = enum {
    info,
    warning,
    err_level,
    low,
    medium,
    high,
    critical,
    unknown,

    pub fn parse(text: []const u8) ?Severity {
        const pairs = [_]struct { name: []const u8, value: Severity }{
            .{ .name = "info", .value = .info },
            .{ .name = "warning", .value = .warning },
            .{ .name = "error", .value = .err_level },
            .{ .name = "low", .value = .low },
            .{ .name = "medium", .value = .medium },
            .{ .name = "high", .value = .high },
            .{ .name = "critical", .value = .critical },
            .{ .name = "unknown", .value = .unknown },
        };
        for (pairs) |pair| if (std.mem.eql(u8, pair.name, text)) return pair.value;
        return null;
    }
};

const Kind = enum {
    ident,
    kw,
    string,
    number,
    lbrace,
    rbrace,
    equals,
    eq,
    neq,
    lt,
    lte,
    gt,
    gte,
    comma,
    dot,
    semi,
    newline,
    eof,
};

const Token = struct {
    kind: Kind,
    text: []const u8 = "",
    value: u32 = 0,
    line: u32 = 0,
};

const keywords = [_][]const u8{
    "script", "do",    "end",  "use",     "budget", "cap",     "step",
    "emit",   "stop",  "info", "warning", "error",  "finding", "from_policy",
    "true",   "false", "if",   "then",    "elseif", "else",    "for",
    "out",    "and",   "or",   "not",     "run",    "fail",
};

fn keywordKind(text: []const u8) bool {
    for (keywords) |item| if (std.mem.eql(u8, item, text)) return true;
    return false;
}

pub const Use = struct { path: []const u8, line: u32 };

pub const Budget = struct {
    time_ms: u32 = 0,
    steps: u32 = 0,
    tx: u32 = 0,
    has_time: bool = false,
    has_steps: bool = false,
    has_tx: bool = false,
};

pub const Value = union(enum) {
    string: []const u8,
    number: u32,
    boolean: bool,
    reference: []const u8,
    policy: void,
};

pub const Option = struct { key: []const u8, value: Value, line: u32 };

pub const Cap = struct {
    name: []const u8,
    verb: []const u8,
    active: bool,
    options: []Option,
    line: u32,
};

pub const Emit = union(enum) {
    finding: []Option,
    plain: struct { level: Severity, message: []const u8 },
};

pub const Call = struct { cap: []const u8, options: []Option, line: u32 };

pub const Assign = struct { name: []const u8, call: Call, line: u32 };

pub const CmpOp = enum { eq, neq, lt, lte, gt, gte };

pub const Operand = union(enum) {
    string: []const u8,
    number: u32,
    path: []const []const u8,
};

pub const Comparison = struct {
    op: CmpOp,
    left: []const []const u8,
    right: Operand,
    line: u32,
};

pub const Connector = enum { and_op, or_op };

pub const Cond = struct {
    negated: bool = false,
    comparisons: []Comparison,
    connectors: []Connector,
};

pub const Out = struct { name: []const u8, line: u32 };

pub const Run = struct { name: []const u8, line: u32 };

/// A named sub-script the caller can inline with "run".
pub const LibraryEntry = struct { name: []const u8, script: *const Script };

pub const Library = struct {
    entries: []const LibraryEntry = &.{},

    pub fn find(self: *const Library, name: []const u8) ?*const Script {
        for (self.entries) |entry| if (std.mem.eql(u8, entry.name, name)) return entry.script;
        return null;
    }
};

pub const If = struct {
    cond: Cond,
    then_body: []Stmt,
    else_body: []Stmt,
    line: u32,
};

pub const For = struct {
    var_name: []const u8,
    count: u32,
    body: []Stmt,
    line: u32,
};

pub const Stmt = union(enum) {
    call: Call,
    assign: Assign,
    emit: Emit,
    fail: []const u8,
    stop: void,
    out: Out,
    run: Run,
    if_stmt: If,
    for_stmt: For,
};

pub const Step = struct { name: []const u8, body: []Stmt, line: u32 };

pub const Script = struct {
    arena: std.heap.ArenaAllocator,
    source: []u8,
    name: []const u8,
    uses: []Use,
    budget: ?Budget,
    caps: []Cap,
    steps: []Step,
    /// Names exported with "out" at step level; visible to a caller that runs this script.
    exports: []const []const u8 = &.{},
    /// Sub-script names declared with use "script:<name>".
    script_imports: []const []const u8 = &.{},
    /// Sub-script names actually referenced by run statements.
    runs: []const []const u8 = &.{},

    pub fn deinit(self: *Script) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn capByName(self: *const Script, name: []const u8) ?Cap {
        for (self.caps) |cap| if (std.mem.eql(u8, cap.name, name)) return cap;
        return null;
    }
};

const VerbInfo = struct { name: []const u8, active: bool };

const verbs = [_]VerbInfo{
    .{ .name = "subghz.read", .active = false },
    .{ .name = "subghz.transmit", .active = true },
    .{ .name = "nfc.read", .active = false },
    .{ .name = "nfc.emulate", .active = true },
    .{ .name = "ir.receive", .active = false },
    .{ .name = "ir.transmit", .active = true },
    .{ .name = "lfrfid.read", .active = false },
    .{ .name = "ibutton.read", .active = false },
    .{ .name = "net.capture", .active = false },
    .{ .name = "net.tls", .active = false },
    .{ .name = "net.scan", .active = false },
    .{ .name = "net.http", .active = false },
    .{ .name = "net.udp", .active = false },
    .{ .name = "net.tcp", .active = false },
    .{ .name = "net.ajp", .active = false },
    .{ .name = "net.h2", .active = false },
    .{ .name = "exploit.plan", .active = false },
    .{ .name = "exploit.execute", .active = true },
    .{ .name = "exploit.adaptive", .active = true },
    .{ .name = "fs.read", .active = false },
    .{ .name = "fs.write", .active = true },
};

const option_keys = [_][]const u8{
    "region",             "on_error",           "into",                   "payload",      "confirm",
    "tag",                "note",               "path",                   "timeout",      "message",
    "severity",           "target",             "method",                 "body",         "expect_status",
    "expect_body",        "expect_absent",      "headers",                "data",         "expect_min_bytes",
    "capture_name",       "capture_prefix",     "capture_suffix",         "observations", "surface",
    "records",            "plan",               "campaign",               "goal",         "body_file",
    "uri",                "server_port",        "attributes",             "path_suffix",  "body_ref",
    "capture_prefix_hex", "capture_suffix_hex", "expect_location_prefix", "headers_file", "stream_id",
};

fn verbInfo(name: []const u8) ?VerbInfo {
    for (verbs) |item| if (std.mem.eql(u8, item.name, name)) return item;
    return null;
}

const PackEntry = struct { name: []const u8, verbs: []const []const u8 };

/// Packs are the capability surface a script must opt into with "use". A verb that
/// belongs to no pack cannot be imported, which keeps the compiler honest when new
/// verbs are added.
const packs = [_]PackEntry{
    .{ .name = "pack.rf", .verbs = &.{ "subghz.read", "subghz.transmit", "lfrfid.read", "ibutton.read" } },
    .{ .name = "pack.nfc", .verbs = &.{ "nfc.read", "nfc.emulate" } },
    .{ .name = "pack.ir", .verbs = &.{ "ir.receive", "ir.transmit" } },
    .{ .name = "pack.net", .verbs = &.{ "net.capture", "net.tls", "net.scan", "net.http", "net.udp", "net.tcp", "net.ajp", "net.h2" } },
    .{ .name = "pack.fs", .verbs = &.{ "fs.read", "fs.write" } },
    .{ .name = "pack.exploit", .verbs = &.{ "exploit.plan", "exploit.execute", "exploit.adaptive" } },
};

pub fn packKnown(name: []const u8) bool {
    for (packs) |entry| if (std.mem.eql(u8, entry.name, name)) return true;
    return false;
}

pub fn packForVerb(verb: []const u8) ?[]const u8 {
    for (packs) |entry| {
        for (entry.verbs) |candidate| {
            if (std.mem.eql(u8, candidate, verb)) return entry.name;
        }
    }
    return null;
}

pub fn packNames() []const []const u8 {
    return &.{ "pack.rf", "pack.nfc", "pack.ir", "pack.net", "pack.fs" };
}

fn allowedOptionKey(name: []const u8) bool {
    for (option_keys) |item| if (std.mem.eql(u8, item, name)) return true;
    return false;
}

fn lex(arena: Allocator, source: []const u8) Error![]Token {
    var tokens: std.ArrayList(Token) = .empty;
    var i: usize = 0;
    var line: u32 = 1;

    while (i < source.len) {
        const c = source[i];
        if (c == ' ' or c == '\t' or c == '\r') {
            i += 1;
        } else if (c == '\n') {
            try tokens.append(arena, .{ .kind = .newline, .line = line });
            line += 1;
            i += 1;
        } else if (c == '-' and i + 1 < source.len and source[i + 1] == '-') {
            while (i < source.len and source[i] != '\n') i += 1;
        } else if (c == '{') {
            try tokens.append(arena, .{ .kind = .lbrace, .line = line });
            i += 1;
        } else if (c == '}') {
            try tokens.append(arena, .{ .kind = .rbrace, .line = line });
            i += 1;
        } else if (c == '=') {
            if (i + 1 < source.len and source[i + 1] == '=') {
                try tokens.append(arena, .{ .kind = .eq, .line = line });
                i += 2;
            } else {
                try tokens.append(arena, .{ .kind = .equals, .line = line });
                i += 1;
            }
        } else if (c == '~') {
            if (i + 1 < source.len and source[i + 1] == '=') {
                try tokens.append(arena, .{ .kind = .neq, .line = line });
                i += 2;
            } else return error.UnexpectedCharacter;
        } else if (c == '<') {
            if (i + 1 < source.len and source[i + 1] == '=') {
                try tokens.append(arena, .{ .kind = .lte, .line = line });
                i += 2;
            } else {
                try tokens.append(arena, .{ .kind = .lt, .line = line });
                i += 1;
            }
        } else if (c == '>') {
            if (i + 1 < source.len and source[i + 1] == '=') {
                try tokens.append(arena, .{ .kind = .gte, .line = line });
                i += 2;
            } else {
                try tokens.append(arena, .{ .kind = .gt, .line = line });
                i += 1;
            }
        } else if (c == ',') {
            try tokens.append(arena, .{ .kind = .comma, .line = line });
            i += 1;
        } else if (c == '.') {
            try tokens.append(arena, .{ .kind = .dot, .line = line });
            i += 1;
        } else if (c == ';') {
            try tokens.append(arena, .{ .kind = .semi, .line = line });
            i += 1;
        } else if (c == '"') {
            const start_line = line;
            i += 1;
            const start = i;
            while (i < source.len and source[i] != '"') {
                if (source[i] == '\n') return error.UnterminatedString;
                i += 1;
            }
            if (i >= source.len) return error.UnterminatedString;
            const text = source[start..i];
            i += 1;
            try tokens.append(arena, .{ .kind = .string, .text = text, .line = start_line });
        } else if (std.ascii.isDigit(c)) {
            const start = i;
            while (i < source.len and (std.ascii.isDigit(source[i]) or source[i] == '_')) i += 1;
            const raw = source[start..i];
            var clean: std.ArrayList(u8) = .empty;
            for (raw) |byte| if (byte != '_') try clean.append(arena, byte);
            const text = try clean.toOwnedSlice(arena);
            const value = std.fmt.parseInt(u32, text, 10) catch return error.InvalidNumber;
            try tokens.append(arena, .{ .kind = .number, .text = text, .value = value, .line = line });
        } else if (std.ascii.isAlphabetic(c) or c == '_') {
            const start = i;
            while (i < source.len and (std.ascii.isAlphanumeric(source[i]) or source[i] == '_')) i += 1;
            const text = source[start..i];
            const kind: Kind = if (keywordKind(text)) .kw else .ident;
            try tokens.append(arena, .{ .kind = kind, .text = text, .line = line });
        } else {
            return error.UnexpectedCharacter;
        }
    }

    try tokens.append(arena, .{ .kind = .eof, .line = line });
    return tokens.toOwnedSlice(arena);
}

const Parser = struct {
    tokens: []const Token,
    allocator: Allocator,
    library: ?*const Library = null,
    index: usize = 0,
    diag: ?Diagnostic = null,

    fn peek(self: *Parser) Token {
        return self.tokens[self.index];
    }

    fn peekAt(self: *Parser, offset: usize) Token {
        const at = self.index + offset;
        if (at >= self.tokens.len) return self.tokens[self.tokens.len - 1];
        return self.tokens[at];
    }

    fn advance(self: *Parser) Token {
        const token = self.tokens[self.index];
        if (self.index + 1 < self.tokens.len) self.index += 1;
        return token;
    }

    fn note(self: *Parser, line: u32, message: []const u8) void {
        if (self.diag == null) self.diag = .{ .line = line, .message = message };
    }

    fn isKw(token: Token, name: []const u8) bool {
        return token.kind == .kw and std.mem.eql(u8, token.text, name);
    }

    fn skipNewlines(self: *Parser) void {
        while (self.peek().kind == .newline or self.peek().kind == .semi) _ = self.advance();
    }

    fn expectKeyword(self: *Parser, name: []const u8) Error!void {
        const token = self.peek();
        if (!isKw(token, name)) {
            self.note(token.line, name);
            return error.UnexpectedToken;
        }
        _ = self.advance();
    }

    fn expectKind(self: *Parser, kind: Kind) Error!Token {
        const token = self.peek();
        if (token.kind != kind) {
            self.note(token.line, @tagName(kind));
            return error.UnexpectedToken;
        }
        return self.advance();
    }

    fn parseValue(self: *Parser) Error!Value {
        const token = self.peek();
        switch (token.kind) {
            .string => {
                _ = self.advance();
                return .{ .string = token.text };
            },
            .number => {
                _ = self.advance();
                return .{ .number = token.value };
            },
            .ident => {
                // A reference is one or more identifiers joined with '.'; it names a
                // script variable ("sig") or one of its bound fields ("sig.version").
                _ = self.advance();
                var text = token.text;
                while (self.peek().kind == .dot) {
                    const dot = self.peek();
                    _ = self.advance();
                    const part = self.peek();
                    if (part.kind != .ident) {
                        self.note(dot.line, "field name after '.'");
                        return error.InvalidReference;
                    }
                    _ = self.advance();
                    text = std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ text, part.text }) catch {
                        return error.OutOfMemory;
                    };
                }
                if (text.len > max_text_bytes) {
                    self.note(token.line, "reference");
                    return error.InvalidReference;
                }
                return .{ .reference = text };
            },
            .kw => {
                if (isKw(token, "true")) {
                    _ = self.advance();
                    return .{ .boolean = true };
                }
                if (isKw(token, "false")) {
                    _ = self.advance();
                    return .{ .boolean = false };
                }
                if (isKw(token, "from_policy")) {
                    _ = self.advance();
                    return .{ .policy = {} };
                }
                self.note(token.line, "value");
                return error.UnexpectedToken;
            },
            else => {
                self.note(token.line, "value");
                return error.UnexpectedToken;
            },
        }
    }

    fn parseOptions(self: *Parser) Error![]Option {
        _ = try self.expectKind(.lbrace);
        var options: std.ArrayList(Option) = .empty;
        const arena = self.arenaOf();

        while (true) {
            self.skipNewlines();
            const token = self.peek();
            if (token.kind == .rbrace) {
                _ = self.advance();
                break;
            }
            if (token.kind == .eof) {
                self.note(token.line, "}");
                return error.UnexpectedToken;
            }
            if (options.items.len >= max_options) {
                self.note(token.line, "options");
                return error.TooManyItems;
            }
            const key = try self.expectKind(.ident);
            _ = try self.expectKind(.equals);
            self.skipNewlines();
            const value = try self.parseValue();
            options.append(arena, .{ .key = key.text, .value = value, .line = key.line }) catch return error.TooManyItems;
            self.skipNewlines();
            if (self.peek().kind == .comma) _ = self.advance();
        }

        return options.toOwnedSlice(arena) catch return error.TooManyItems;
    }

    fn arenaOf(self: *Parser) Allocator {
        return self.allocator;
    }

    fn parseCall(self: *Parser) Error!Call {
        const name = try self.expectKind(.ident);
        const options = try self.parseOptions();
        return .{ .cap = name.text, .options = options, .line = name.line };
    }

    fn parseEmit(self: *Parser) Error!Emit {
        const arena = self.arenaOf();
        const token = self.peek();
        if (isKw(token, "finding")) {
            _ = self.advance();
            return .{ .finding = try self.parseOptions() };
        }
        const level: Severity = if (isKw(token, "info"))
            .info
        else if (isKw(token, "warning"))
            .warning
        else if (isKw(token, "error"))
            .err_level
        else {
            self.note(token.line, "info|warning|error|finding");
            return error.UnexpectedToken;
        };
        _ = self.advance();
        const message = try self.expectKind(.string);
        if (message.text.len == 0) {
            self.note(message.line, "message");
            return error.MissingMessage;
        }
        if (message.text.len > max_text_bytes) return error.TooManyItems;
        _ = arena;
        return .{ .plain = .{ .level = level, .message = message.text } };
    }

    fn parseStatement(self: *Parser) Error!Stmt {
        const token = self.peek();
        if (token.kind == .ident) {
            const next = self.peekAt(1);
            if (next.kind == .equals) {
                const name = self.advance();
                _ = self.advance();
                self.skipNewlines();
                const call = try self.parseCall();
                return .{ .assign = .{ .name = name.text, .call = call, .line = name.line } };
            }
            return .{ .call = try self.parseCall() };
        }
        if (isKw(token, "emit")) {
            _ = self.advance();
            self.skipNewlines();
            return .{ .emit = try self.parseEmit() };
        }
        if (isKw(token, "stop")) {
            _ = self.advance();
            return .{ .stop = {} };
        }
        if (isKw(token, "fail")) {
            _ = self.advance();
            const message = try self.expectKind(.string);
            if (message.text.len == 0 or message.text.len > 512) {
                self.note(message.line, "fail message");
                return error.InvalidScriptName;
            }
            return .{ .fail = message.text };
        }
        if (isKw(token, "out")) {
            _ = self.advance();
            const name = try self.expectKind(.ident);
            return .{ .out = .{ .name = name.text, .line = name.line } };
        }
        if (isKw(token, "run")) {
            _ = self.advance();
            const name = try self.expectKind(.string);
            return .{ .run = .{ .name = name.text, .line = name.line } };
        }
        if (isKw(token, "if")) return .{ .if_stmt = try self.parseIf() };
        if (isKw(token, "for")) return .{ .for_stmt = try self.parseFor() };
        self.note(token.line, "statement");
        return error.UnexpectedToken;
    }

    fn parsePath(self: *Parser) Error![]const []const u8 {
        const arena = self.arenaOf();
        var parts: std.ArrayList([]const u8) = .empty;
        const first = try self.expectKind(.ident);
        try parts.append(arena, first.text);
        while (self.peek().kind == .dot) {
            _ = self.advance();
            const part = try self.expectKind(.ident);
            try parts.append(arena, part.text);
        }
        return parts.toOwnedSlice(arena) catch return error.TooManyItems;
    }

    fn parseOperand(self: *Parser) Error!Operand {
        const token = self.peek();
        switch (token.kind) {
            .string => {
                _ = self.advance();
                return .{ .string = token.text };
            },
            .number => {
                _ = self.advance();
                return .{ .number = token.value };
            },
            .ident => return .{ .path = try self.parsePath() },
            else => {
                self.note(token.line, "operand");
                return error.UnexpectedToken;
            },
        }
    }

    fn parseComparison(self: *Parser) Error!Comparison {
        const start = self.peek();
        const left = try self.parsePath();
        const token = self.peek();
        const op: CmpOp = switch (token.kind) {
            .eq => .eq,
            .neq => .neq,
            .lt => .lt,
            .lte => .lte,
            .gt => .gt,
            .gte => .gte,
            else => {
                self.note(token.line, "comparison operator");
                return error.UnexpectedToken;
            },
        };
        _ = self.advance();
        self.skipNewlines();
        const right = try self.parseOperand();
        return .{ .op = op, .left = left, .right = right, .line = start.line };
    }

    fn parseCond(self: *Parser) Error!Cond {
        const arena = self.arenaOf();
        var negated = false;
        if (isKw(self.peek(), "not")) {
            _ = self.advance();
            negated = true;
        }
        var comparisons: std.ArrayList(Comparison) = .empty;
        var connectors: std.ArrayList(Connector) = .empty;
        try comparisons.append(arena, try self.parseComparison());
        while (true) {
            const token = self.peek();
            const connector: Connector = if (isKw(token, "and"))
                .and_op
            else if (isKw(token, "or"))
                .or_op
            else
                break;
            _ = self.advance();
            try connectors.append(arena, connector);
            self.skipNewlines();
            try comparisons.append(arena, try self.parseComparison());
        }
        return .{
            .negated = negated,
            .comparisons = try comparisons.toOwnedSlice(arena),
            .connectors = try connectors.toOwnedSlice(arena),
        };
    }

    fn parseBlockBody(self: *Parser) Error![]Stmt {
        const arena = self.arenaOf();
        var body: std.ArrayList(Stmt) = .empty;
        while (true) {
            self.skipNewlines();
            const token = self.peek();
            if (token.kind == .eof) {
                self.note(token.line, "end");
                return error.MissingEnd;
            }
            if (isKw(token, "end") or isKw(token, "else") or isKw(token, "elseif")) break;
            if (body.items.len >= max_statements_per_step) {
                self.note(token.line, "statements");
                return error.TooManyItems;
            }
            body.append(arena, try self.parseStatement()) catch return error.TooManyItems;
        }
        return body.toOwnedSlice(arena) catch return error.TooManyItems;
    }

    fn parseIf(self: *Parser) Error!If {
        const arena = self.arenaOf();
        const keyword = self.peek();
        _ = try self.expectKeyword("if");
        const cond = try self.parseCond();
        try self.expectKeyword("then");
        const then_body = try self.parseBlockBody();

        var else_body: []Stmt = &.{};
        if (isKw(self.peek(), "elseif")) {
            const nested = try self.parseIfTail();
            else_body = arena.dupe(Stmt, &.{.{ .if_stmt = nested }}) catch return error.TooManyItems;
        } else if (isKw(self.peek(), "else")) {
            _ = self.advance();
            else_body = try self.parseBlockBody();
            _ = try self.expectKeyword("end");
        } else {
            _ = try self.expectKeyword("end");
        }
        return .{ .cond = cond, .then_body = then_body, .else_body = else_body, .line = keyword.line };
    }

    /// Parses the remainder of an elseif chain; consumes the shared closing end.
    fn parseIfTail(self: *Parser) Error!If {
        const arena = self.arenaOf();
        const keyword = self.peek();
        _ = try self.expectKeyword("elseif");
        const cond = try self.parseCond();
        try self.expectKeyword("then");
        const then_body = try self.parseBlockBody();

        var else_body: []Stmt = &.{};
        if (isKw(self.peek(), "elseif")) {
            const nested = try self.parseIfTail();
            else_body = arena.dupe(Stmt, &.{.{ .if_stmt = nested }}) catch return error.TooManyItems;
        } else if (isKw(self.peek(), "else")) {
            _ = self.advance();
            else_body = try self.parseBlockBody();
            _ = try self.expectKeyword("end");
        } else {
            _ = try self.expectKeyword("end");
        }
        return .{ .cond = cond, .then_body = then_body, .else_body = else_body, .line = keyword.line };
    }

    fn parseFor(self: *Parser) Error!For {
        const keyword = self.peek();
        _ = try self.expectKeyword("for");
        const name = try self.expectKind(.ident);
        _ = try self.expectKind(.equals);
        const start = try self.expectKind(.number);
        _ = try self.expectKind(.comma);
        const end = try self.expectKind(.number);
        if (start.value != 1) {
            self.note(start.line, "for 1,N");
            return error.InvalidLoopBound;
        }
        if (end.value == 0 or end.value > max_loop_count) {
            self.note(end.line, "loop bound");
            return error.InvalidLoopBound;
        }
        try self.expectKeyword("do");
        const body = try self.parseBlockBody();
        _ = try self.expectKeyword("end");
        return .{ .var_name = name.text, .count = end.value, .body = body, .line = keyword.line };
    }

    fn parseStep(self: *Parser) Error!Step {
        const arena = self.arenaOf();
        _ = try self.expectKeyword("step");
        const name = try self.expectKind(.string);
        if (name.text.len == 0 or name.text.len > max_name_bytes) {
            self.note(name.line, "step name");
            return error.InvalidScriptName;
        }
        try self.expectKeyword("do");

        var body: std.ArrayList(Stmt) = .empty;
        while (true) {
            self.skipNewlines();
            const token = self.peek();
            if (token.kind == .eof) {
                self.note(token.line, "end");
                return error.MissingEnd;
            }
            if (isKw(token, "end")) {
                _ = self.advance();
                break;
            }
            if (body.items.len >= max_statements_per_step) {
                self.note(token.line, "statements");
                return error.TooManyItems;
            }
            body.append(arena, try self.parseStatement()) catch return error.TooManyItems;
        }
        return .{ .name = name.text, .body = body.toOwnedSlice(arena) catch return error.TooManyItems, .line = name.line };
    }

    fn parseBudget(self: *Parser) Error!Budget {
        _ = try self.expectKeyword("budget");
        const options = try self.parseOptions();
        var budget = Budget{};
        for (options) |option| {
            if (std.mem.eql(u8, option.key, "time")) {
                if (budget.has_time) {
                    self.note(option.line, "time");
                    return error.DuplicateBudgetKey;
                }
                const text = switch (option.value) {
                    .string => |value| value,
                    else => {
                        self.note(option.line, "duration string");
                        return error.InvalidDuration;
                    },
                };
                budget.time_ms = parseDuration(text) orelse {
                    self.note(option.line, "duration");
                    return error.InvalidDuration;
                };
                budget.has_time = true;
            } else if (std.mem.eql(u8, option.key, "steps")) {
                const value = switch (option.value) {
                    .number => |number| number,
                    else => {
                        self.note(option.line, "steps");
                        return error.InvalidNumber;
                    },
                };
                if (budget.has_steps) {
                    self.note(option.line, "steps");
                    return error.DuplicateBudgetKey;
                }
                budget.steps = value;
                budget.has_steps = true;
            } else if (std.mem.eql(u8, option.key, "tx")) {
                const value = switch (option.value) {
                    .number => |number| number,
                    else => {
                        self.note(option.line, "tx");
                        return error.InvalidNumber;
                    },
                };
                if (budget.has_tx) {
                    self.note(option.line, "tx");
                    return error.DuplicateBudgetKey;
                }
                budget.tx = value;
                budget.has_tx = true;
            } else {
                self.note(option.line, "time|steps|tx");
                return error.InvalidBudgetKey;
            }
        }
        return budget;
    }

    fn parseTopLevel(self: *Parser, script_caps: *std.ArrayList(Cap), uses: *std.ArrayList(Use), steps: *std.ArrayList(Step)) Error!?Budget {
        const arena = self.arenaOf();
        const token = self.peek();
        if (isKw(token, "use")) {
            _ = self.advance();
            const path = try self.expectKind(.string);
            if (uses.items.len >= max_uses) {
                self.note(path.line, "use");
                return error.TooManyItems;
            }
            uses.append(arena, .{ .path = path.text, .line = path.line }) catch return error.TooManyItems;
            return null;
        }
        if (isKw(token, "budget")) return try self.parseBudget();
        if (isKw(token, "cap")) {
            _ = self.advance();
            const name = try self.expectKind(.ident);
            _ = try self.expectKind(.equals);
            const verb_token = try self.expectKind(.ident);
            const verb_text = try self.expectVerbText(verb_token);
            const info = verbInfo(verb_text) orelse {
                self.note(verb_token.line, "verb");
                return error.UnknownVerb;
            };
            var options: []Option = &.{};
            self.skipNewlines();
            if (self.peek().kind == .lbrace) options = try self.parseOptions();
            if (script_caps.items.len >= max_caps) {
                self.note(name.line, "cap");
                return error.TooManyItems;
            }
            for (script_caps.items) |existing| {
                if (std.mem.eql(u8, existing.name, name.text)) {
                    self.note(name.line, "cap name");
                    return error.DuplicateCap;
                }
            }
            script_caps.append(arena, .{
                .name = name.text,
                .verb = verb_text,
                .active = info.active,
                .options = options,
                .line = name.line,
            }) catch return error.TooManyItems;
            return null;
        }
        if (isKw(token, "step")) {
            if (steps.items.len >= max_steps) {
                self.note(token.line, "step");
                return error.TooManyItems;
            }
            steps.append(arena, try self.parseStep()) catch return error.TooManyItems;
            return null;
        }
        self.note(token.line, "use|budget|cap|step");
        return error.UnexpectedToken;
    }

    fn expectVerbText(self: *Parser, first: Token) Error![]const u8 {
        const arena = self.arenaOf();
        var buffer: std.ArrayList(u8) = .empty;
        buffer.appendSlice(arena, first.text) catch return error.TooManyItems;
        while (self.peek().kind == .dot) {
            _ = self.advance();
            const part = try self.expectKind(.ident);
            buffer.append(arena, '.') catch return error.TooManyItems;
            buffer.appendSlice(arena, part.text) catch return error.TooManyItems;
        }
        return buffer.toOwnedSlice(arena) catch return error.TooManyItems;
    }
};

fn parseDuration(text: []const u8) ?u32 {
    var digits: usize = 0;
    while (digits < text.len and std.ascii.isDigit(text[digits])) digits += 1;
    if (digits == 0 or digits > 9) return null;
    const value = std.fmt.parseInt(u32, text[0..digits], 10) catch return null;
    const unit = text[digits..];
    const multiplier: u32 = if (std.mem.eql(u8, unit, "ms"))
        1
    else if (std.mem.eql(u8, unit, "s"))
        1000
    else if (std.mem.eql(u8, unit, "m"))
        60_000
    else
        return null;
    const total: u64 = @as(u64, value) * @as(u64, multiplier);
    if (total > max_time_ms) return null;
    return @intCast(total);
}

pub const ParseError = struct {
    code: Error,
    diagnostic: ?Diagnostic = null,
};

pub fn parse(allocator: Allocator, data: []const u8) Error!Script {
    return parseDetailed(allocator, data);
}

pub fn parseDetailed(allocator: Allocator, data: []const u8) Error!Script {
    return parseWithLibrary(allocator, data, null);
}

/// Parses and validates a script against a library of sub-scripts. "run" and
/// use "script:<name>" only resolve when the library is supplied, so a script that
/// composes others cannot be validated in isolation.
pub fn parseWithLibrary(allocator: Allocator, data: []const u8, library: ?*const Library) Error!Script {
    if (data.len > max_script_bytes) return error.ScriptTooLarge;

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    const source = try arena_allocator.dupe(u8, data);
    const tokens = try lex(arena_allocator, source);

    var parser = Parser{ .tokens = tokens, .allocator = arena_allocator, .library = library };

    parser.skipNewlines();
    if (parser.peek().kind == .eof) return error.EmptyScript;

    try parser.expectKeyword("script");
    const name = try parser.expectKind(.string);
    if (name.text.len == 0 or name.text.len > max_name_bytes) {
        parser.note(name.line, "script name");
        return error.InvalidScriptName;
    }
    try parser.expectKeyword("do");

    var uses: std.ArrayList(Use) = .empty;
    var caps: std.ArrayList(Cap) = .empty;
    var steps: std.ArrayList(Step) = .empty;
    var budget: ?Budget = null;

    while (true) {
        parser.skipNewlines();
        const token = parser.peek();
        if (token.kind == .eof) {
            parser.note(token.line, "end");
            return error.MissingEnd;
        }
        if (Parser.isKw(token, "end")) {
            _ = parser.advance();
            break;
        }
        if (try parser.parseTopLevel(&caps, &uses, &steps)) |parsed_budget| {
            if (budget != null) {
                parser.note(token.line, "budget");
                return error.DuplicateBudgetKey;
            }
            budget = parsed_budget;
        }
    }

    parser.skipNewlines();
    if (parser.peek().kind != .eof) {
        parser.note(parser.peek().line, "eof");
        return error.TrailingInput;
    }

    if (steps.items.len == 0) {
        parser.note(name.line, "step");
        return error.EmptyScript;
    }

    // Validate before moving the arena into the result: the errdefer above must stay
    // the only owner on failure (deiniting both would double free).
    var candidate = Script{
        .arena = undefined,
        .source = source,
        .name = name.text,
        .uses = try uses.toOwnedSlice(arena_allocator),
        .budget = budget,
        .caps = try caps.toOwnedSlice(arena_allocator),
        .steps = try steps.toOwnedSlice(arena_allocator),
    };
    try validateScript(&parser, &candidate);
    candidate.arena = arena;
    return candidate;
}

fn validOnError(text: []const u8) bool {
    if (std.mem.eql(u8, text, "abort") or std.mem.eql(u8, text, "continue")) return true;
    if (!std.mem.startsWith(u8, text, "retry(") or !std.mem.endsWith(u8, text, ")")) return false;
    const inner = text[6 .. text.len - 1];
    if (inner.len == 0) return false;
    _ = std.fmt.parseInt(u16, inner, 10) catch return false;
    return true;
}

fn validateCapOptions(parser: *Parser, cap: Cap) Error!void {
    for (cap.options) |option| {
        if (!allowedOptionKey(option.key)) {
            parser.note(option.line, "option key");
            return error.UnknownOptionKey;
        }
        if (std.mem.eql(u8, option.key, "region")) {
            switch (option.value) {
                .string, .policy => {},
                else => {
                    parser.note(option.line, "region string or from_policy");
                    return error.UnknownOptionKey;
                },
            }
        }
        if (std.mem.eql(u8, option.key, "on_error")) {
            const text = switch (option.value) {
                .string => |value| value,
                else => {
                    parser.note(option.line, "on_error string");
                    return error.UnknownOptionKey;
                },
            };
            if (!validOnError(text)) {
                parser.note(option.line, "on_error abort|continue|retry(n)");
                return error.UnknownOptionKey;
            }
        }
    }
}

fn nameIn(names: []const []const u8, name: []const u8) bool {
    for (names) |item| if (std.mem.eql(u8, item, name)) return true;
    return false;
}

fn declareName(allocator: Allocator, list: *std.ArrayList([]const u8), name: []const u8) Error!void {
    if (!nameIn(list.items, name)) list.append(allocator, name) catch return error.TooManyItems;
}

const ValidateContext = struct {
    parser: *Parser,
    script: *const Script,
    packs: *std.ArrayList([]const u8),
    script_imports: *std.ArrayList([]const u8),
    exported: *std.ArrayList([]const u8),
    runs: *std.ArrayList([]const u8),
};

fn validateScript(parser: *Parser, script: *Script) Error!void {
    var imported_packs: std.ArrayList([]const u8) = .empty;
    defer imported_packs.deinit(parser.allocator);
    var script_imports: std.ArrayList([]const u8) = .empty;
    defer script_imports.deinit(parser.allocator);
    var exported: std.ArrayList([]const u8) = .empty;
    defer exported.deinit(parser.allocator);
    var runs: std.ArrayList([]const u8) = .empty;
    defer runs.deinit(parser.allocator);

    for (script.uses) |usage| {
        if (usage.path.len == 0 or usage.path.len > max_name_bytes) {
            parser.note(usage.line, "use path");
            return error.InvalidUse;
        }
        if (std.mem.startsWith(u8, usage.path, "pack.")) {
            if (!packKnown(usage.path)) {
                parser.note(usage.line, "unknown pack");
                return error.UnknownPack;
            }
            try declareName(parser.allocator, &imported_packs, usage.path);
        } else if (std.mem.startsWith(u8, usage.path, "script:")) {
            const name = usage.path["script:".len..];
            if (name.len == 0 or name.len > max_name_bytes) {
                parser.note(usage.line, "script name");
                return error.InvalidUse;
            }
            const library = parser.library orelse {
                parser.note(usage.line, "no script library was provided");
                return error.UnknownScript;
            };
            if (library.find(name) == null) {
                parser.note(usage.line, "unknown sub-script");
                return error.UnknownScript;
            }
            try declareName(parser.allocator, &script_imports, name);
        } else {
            parser.note(usage.line, "use pack.<name> or script:<name>");
            return error.InvalidUse;
        }
    }

    for (script.caps) |cap| {
        try validateCapOptions(parser, cap);
        const pack = packForVerb(cap.verb) orelse {
            parser.note(cap.line, "verb has no pack");
            return error.UnknownVerb;
        };
        if (!nameIn(imported_packs.items, pack)) {
            parser.note(cap.line, "missing use of the pack that owns this verb");
            return error.PackNotImported;
        }
    }

    var context = ValidateContext{
        .parser = parser,
        .script = script,
        .packs = &imported_packs,
        .script_imports = &script_imports,
        .exported = &exported,
        .runs = &runs,
    };

    for (script.steps, 0..) |step, index| {
        for (script.steps[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, step.name)) {
                parser.note(step.line, "step name");
                return error.InvalidScriptName;
            }
        }
        try validateStep(&context, step);
    }

    script.exports = parser.allocator.dupe([]const u8, exported.items) catch return error.OutOfMemory;
    script.script_imports = parser.allocator.dupe([]const u8, script_imports.items) catch return error.OutOfMemory;
    script.runs = parser.allocator.dupe([]const u8, runs.items) catch return error.OutOfMemory;
}

fn validateStep(context: *ValidateContext, step: Step) Error!void {
    const parser = context.parser;
    var visible: std.ArrayList([]const u8) = .empty;
    defer visible.deinit(parser.allocator);
    visible.appendSlice(parser.allocator, context.exported.items) catch return error.TooManyItems;

    var local: std.ArrayList([]const u8) = .empty;
    defer local.deinit(parser.allocator);

    try validateStmts(context, step.body, &visible, &local, true);
}

fn validateStmts(
    context: *ValidateContext,
    statements: []Stmt,
    visible: *std.ArrayList([]const u8),
    local: *std.ArrayList([]const u8),
    is_step_top: bool,
) Error!void {
    const parser = context.parser;
    const script = context.script;

    for (statements) |statement| {
        switch (statement) {
            .call => |call| try validateCall(parser, script, call, visible.items),
            .assign => |assign| {
                if (script.capByName(assign.name) != null) {
                    parser.note(assign.line, "variable name clashes with cap");
                    return error.DuplicateVariable;
                }
                if (nameIn(local.items, assign.name)) {
                    parser.note(assign.line, "variable");
                    return error.DuplicateVariable;
                }
                try declareName(parser.allocator, local, assign.name);
                try declareName(parser.allocator, visible, assign.name);
                try validateCall(parser, script, assign.call, visible.items);
            },
            .emit => |emit| try validateEmit(parser, emit, visible.items),
            .fail => {},
            .stop => {},
            .out => |out| {
                if (!nameIn(visible.items, out.name)) {
                    parser.note(out.line, "out variable must be assigned first");
                    return error.UnknownVariable;
                }
                if (is_step_top) try declareName(parser.allocator, context.exported, out.name);
            },
            .run => |run| {
                if (!nameIn(context.script_imports.items, run.name)) {
                    parser.note(run.line, "run target was not imported");
                    return error.UnknownScript;
                }
                const library = parser.library orelse {
                    parser.note(run.line, "no script library was provided");
                    return error.UnknownScript;
                };
                const target = library.find(run.name) orelse {
                    parser.note(run.line, "unknown sub-script");
                    return error.UnknownScript;
                };
                try declareName(parser.allocator, context.runs, run.name);
                // The sub-script's exports become readable in the caller at this point.
                for (target.exports) |name| try declareName(parser.allocator, visible, name);
            },
            .if_stmt => |branch| {
                try validateCond(parser, branch.cond, visible.items);
                const mark = visible.items.len;
                try validateStmts(context, branch.then_body, visible, local, false);
                visible.shrinkRetainingCapacity(mark);
                try validateStmts(context, branch.else_body, visible, local, false);
                visible.shrinkRetainingCapacity(mark);
            },
            .for_stmt => |loop| {
                const mark = visible.items.len;
                try declareName(parser.allocator, visible, loop.var_name);
                try validateStmts(context, loop.body, visible, local, false);
                visible.shrinkRetainingCapacity(mark);
            },
        }
    }
}

fn validateCond(parser: *Parser, cond: Cond, visible: []const []const u8) Error!void {
    for (cond.comparisons) |comparison| {
        if (comparison.left.len == 0 or !nameIn(visible, comparison.left[0])) {
            parser.note(comparison.line, "condition references an unknown variable");
            return error.UnknownVariable;
        }
        switch (comparison.right) {
            .path => |path| {
                if (path.len > 0 and !nameIn(visible, path[0])) {
                    parser.note(comparison.line, "condition references an unknown variable");
                    return error.UnknownVariable;
                }
            },
            else => {},
        }
    }
}

fn referenceRoot(reference: []const u8) []const u8 {
    const dot = std.mem.indexOfScalar(u8, reference, '.') orelse return reference;
    return reference[0..dot];
}

/// A reference must name a variable that is already visible: either assigned earlier in
/// the same statement list or exported by a previous step. Unknown roots are rejected at
/// parse time so a typo cannot silently become an empty payload at run time.
fn validateReference(parser: *Parser, line: u32, reference: []const u8, visible: []const []const u8) Error!void {
    const root = referenceRoot(reference);
    if (root.len == 0 or !nameIn(visible, root)) {
        parser.note(line, "reference to an unknown variable");
        return error.UnknownVariable;
    }
}

fn validateCall(parser: *Parser, script: *const Script, call: Call, visible: []const []const u8) Error!void {
    if (script.capByName(call.cap) == null) {
        parser.note(call.line, "declared cap");
        return error.UndeclaredCap;
    }
    for (call.options) |option| {
        if (!allowedOptionKey(option.key)) {
            parser.note(option.line, "option key");
            return error.UnknownOptionKey;
        }
        if (std.mem.eql(u8, option.key, "payload")) {
            switch (option.value) {
                .string => {},
                .reference => |reference| try validateReference(parser, option.line, reference, visible),
                else => {
                    parser.note(option.line, "payload string or variable reference");
                    return error.InvalidOptionValue;
                },
            }
        } else if (std.mem.eql(u8, option.key, "region")) {
            switch (option.value) {
                .string, .policy => {},
                else => {
                    parser.note(option.line, "region string or from_policy");
                    return error.InvalidOptionValue;
                },
            }
        }
    }
}

fn validateEmit(parser: *Parser, emit: Emit, visible: []const []const u8) Error!void {
    switch (emit) {
        .plain => |plain| {
            if (plain.message.len > max_text_bytes) return error.TooManyItems;
        },
        .finding => |options| {
            var has_severity = false;
            var has_message = false;
            for (options) |option| {
                if (!allowedOptionKey(option.key)) {
                    parser.note(option.line, "option key");
                    return error.UnknownOptionKey;
                }
                if (std.mem.eql(u8, option.key, "severity")) {
                    switch (option.value) {
                        .string => |text| {
                            if (Severity.parse(text) == null) {
                                parser.note(option.line, "severity value");
                                return error.InvalidSeverity;
                            }
                        },
                        .reference => |reference| try validateReference(parser, option.line, reference, visible),
                        else => {
                            parser.note(option.line, "severity string or variable reference");
                            return error.InvalidSeverity;
                        },
                    }
                    has_severity = true;
                }
                if (std.mem.eql(u8, option.key, "message") or
                    std.mem.eql(u8, option.key, "tag") or
                    std.mem.eql(u8, option.key, "note"))
                {
                    switch (option.value) {
                        .string => |text| {
                            if (text.len > max_text_bytes) {
                                parser.note(option.line, "text");
                                return error.TooManyItems;
                            }
                            if (std.mem.eql(u8, option.key, "message")) {
                                if (text.len == 0) {
                                    parser.note(option.line, "message");
                                    return error.MissingMessage;
                                }
                                has_message = true;
                            }
                        },
                        .reference => |reference| {
                            try validateReference(parser, option.line, reference, visible);
                            if (std.mem.eql(u8, option.key, "message")) has_message = true;
                        },
                        else => {
                            parser.note(option.line, "text or variable reference");
                            return error.InvalidOptionValue;
                        },
                    }
                }
            }
            if (!has_severity) return error.MissingSeverity;
            if (!has_message) return error.MissingMessage;
        },
    }
}

test "parses a canonical script" {
    var script = try parse(std.testing.allocator,
        \\-- replay sample
        \\script "replay-subghz" do
        \\    use "pack.rf"
        \\    budget { time = "10s", steps = 500, tx = 2 }
        \\    cap rf_capture = subghz.read
        \\    cap rf_tx = subghz.transmit { region = from_policy, on_error = "retry(2)" }
        \\    step "capture" do
        \\        sig = rf_capture { into = "artifact" }
        \\        emit finding { severity = "info", message = "captured" }
        \\    end
        \\    step "send" do
        \\        rf_tx { payload = "raw", on_error = "continue" }
        \\        stop
        \\    end
        \\end
    );
    defer script.deinit();

    try std.testing.expectEqualStrings("replay-subghz", script.name);
    try std.testing.expectEqual(@as(usize, 1), script.uses.len);
    try std.testing.expectEqualStrings("pack.rf", script.uses[0].path);
    try std.testing.expectEqual(@as(u32, 10_000), script.budget.?.time_ms);
    try std.testing.expectEqual(@as(u32, 500), script.budget.?.steps);
    try std.testing.expectEqual(@as(u32, 2), script.budget.?.tx);
    try std.testing.expectEqual(@as(usize, 2), script.caps.len);
    try std.testing.expect(script.caps[0].active == false);
    try std.testing.expect(script.caps[1].active == true);
    try std.testing.expectEqual(@as(usize, 2), script.steps.len);
    try std.testing.expectEqual(@as(usize, 2), script.steps[0].body.len);
    switch (script.steps[0].body[0]) {
        .assign => |assign| try std.testing.expectEqualStrings("sig", assign.name),
        else => return error.UnexpectedToken,
    }
}

test "rejects unknown verbs" {
    try std.testing.expectError(error.UnknownVerb, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    cap bad = subghz.explode
        \\    step "s" do
        \\        stop
        \\    end
        \\end
    ));
}

test "rejects missing end" {
    try std.testing.expectError(error.MissingEnd, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    step "s" do
        \\        stop
        \\    end
    ));
}

test "rejects undeclared capabilities" {
    try std.testing.expectError(error.UndeclaredCap, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    step "s" do
        \\        ghost { payload = "raw" }
        \\    end
        \\end
    ));
}

test "rejects duplicate variables inside a step" {
    try std.testing.expectError(error.DuplicateVariable, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    cap rf_capture = subghz.read
        \\    step "s" do
        \\        sig = rf_capture { into = "artifact" }
        \\        sig = rf_capture { into = "artifact" }
        \\    end
        \\end
    ));
}

test "rejects non-pack uses and invalid durations" {
    try std.testing.expectError(error.InvalidUse, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    use "file:other"
        \\    step "s" do
        \\        stop
        \\    end
        \\end
    ));
    try std.testing.expectError(error.InvalidDuration, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    budget { time = "10 minutes" }
        \\    step "s" do
        \\        stop
        \\    end
        \\end
    ));
}

test "rejects invalid severities and unknown option keys" {
    try std.testing.expectError(error.InvalidSeverity, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    step "s" do
        \\        emit finding { severity = "apocalyptic", message = "m" }
        \\    end
        \\end
    ));
    try std.testing.expectError(error.UnknownOptionKey, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    cap rf_tx = subghz.transmit { nonsense = "x" }
        \\    step "s" do
        \\        stop
        \\    end
        \\end
    ));
}

test "rejects unterminated strings and trailing input" {
    try std.testing.expectError(error.UnterminatedString, parse(
        std.testing.allocator,
        "script \"x\" do\n    step \"s\" do\n        emit info \"oops\n    end\nend\n",
    ));
    try std.testing.expectError(error.TrailingInput, parse(std.testing.allocator,
        \\script "x" do
        \\    use "pack.rf"
        \\    step "s" do
        \\        stop
        \\    end
        \\end
        \\extra
    ));
}

test "rejects oversized sources" {
    var buffer: [max_script_bytes + 1]u8 = undefined;
    @memset(&buffer, ' ');
    try std.testing.expectError(error.ScriptTooLarge, parse(std.testing.allocator, &buffer));
}

test "indentation is not significant" {
    var script = try parse(
        std.testing.allocator,
        "script \"flat\" do\nstep \"s\" do\nstop\nend\nend\n",
    );
    defer script.deinit();
    try std.testing.expectEqualStrings("flat", script.name);
    try std.testing.expectEqual(@as(usize, 1), script.steps.len);
}

test "rejects a cap whose pack was not imported" {
    try std.testing.expectError(error.PackNotImported, parse(std.testing.allocator,
        \\script "no-pack" do
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        rf { payload = "p" }
        \\    end
        \\end
    ));
}

test "rejects unknown packs" {
    try std.testing.expectError(error.UnknownPack, parse(std.testing.allocator,
        \\script "ghost-pack" do
        \\    use "pack.ghost"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        rf { payload = "p" }
        \\    end
        \\end
    ));
}

test "rejects a verb from a pack that was not imported" {
    try std.testing.expectError(error.PackNotImported, parse(std.testing.allocator,
        \\script "wrong-pack" do
        \\    use "pack.rf"
        \\    cap net = net.scan
        \\    step "s" do
        \\        net { payload = "p" }
        \\    end
        \\end
    ));
}

test "packForVerb covers every declared verb" {
    for (verbs) |entry| {
        try std.testing.expect(packForVerb(entry.name) != null);
    }
}

test "run requires an imported sub-script" {
    try std.testing.expectError(error.UnknownScript, parse(std.testing.allocator,
        \\script "orphan" do
        \\    use "pack.rf"
        \\    step "s" do
        \\        run "helper"
        \\    end
        \\end
    ));
}

test "a run target must exist in the library" {
    try std.testing.expectError(error.UnknownScript, parseWithLibrary(std.testing.allocator,
        \\script "missing" do
        \\    use "script:helper"
        \\    step "s" do
        \\        run "helper"
        \\    end
        \\end
    , &.{}));
}

test "a sub-script export becomes visible after run" {
    var helper = try parse(std.testing.allocator,
        \\script "helper" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "capture" do
        \\        sig = rf { payload = "protocol=Princeton" }
        \\        out sig
        \\    end
        \\end
    );
    defer helper.deinit();

    const library = Library{ .entries = &.{.{ .name = "helper", .script = &helper }} };
    var caller = try parseWithLibrary(std.testing.allocator,
        \\script "caller" do
        \\    use "pack.rf"
        \\    use "script:helper"
        \\    cap rf = subghz.read
        \\    step "decide" do
        \\        run "helper"
        \\        if sig.protocol == "Princeton" then
        \\            rf { payload = "match" }
        \\        end
        \\    end
        \\end
    , &library);
    defer caller.deinit();

    // The helper is the one exporting; the caller only records what it ran.
    try std.testing.expectEqual(@as(usize, 1), helper.exports.len);
    try std.testing.expectEqualStrings("sig", helper.exports[0]);
    try std.testing.expectEqual(@as(usize, 0), caller.exports.len);
    try std.testing.expectEqual(@as(usize, 1), caller.runs.len);
    try std.testing.expectEqualStrings("helper", caller.runs[0]);
}

test "parses dotted variable references in call and emit options" {
    var script = try parse(std.testing.allocator,
        \\script "refs" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        sig = rf { payload = "protocol=Princeton" }
        \\        rf { payload = sig.protocol }
        \\        emit finding { severity = "info", message = sig.protocol, tag = sig.name }
        \\    end
        \\end
    );
    defer script.deinit();

    const step = script.steps[0];
    const call = switch (step.body[1]) {
        .call => |value| value,
        else => return error.UnexpectedToken,
    };
    try std.testing.expectEqualStrings("payload", call.options[0].key);
    switch (call.options[0].value) {
        .reference => |reference| try std.testing.expectEqualStrings("sig.protocol", reference),
        else => return error.UnexpectedToken,
    }

    const emit = switch (step.body[2]) {
        .emit => |value| value,
        else => return error.UnexpectedToken,
    };
    const finding = switch (emit) {
        .finding => |options| options,
        else => return error.UnexpectedToken,
    };
    try std.testing.expectEqual(@as(usize, 3), finding.len);
    switch (finding[1].value) {
        .reference => |reference| try std.testing.expectEqualStrings("sig.protocol", reference),
        else => return error.UnexpectedToken,
    }
    switch (finding[2].value) {
        .reference => |reference| try std.testing.expectEqualStrings("sig.name", reference),
        else => return error.UnexpectedToken,
    }
}

test "rejects references to variables that are not visible" {
    try std.testing.expectError(error.UnknownVariable, parse(std.testing.allocator,
        \\script "bad-ref" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        rf { payload = missing.value }
        \\    end
        \\end
    ));
}

test "rejects a trailing dot in a reference" {
    try std.testing.expectError(error.InvalidReference, parse(std.testing.allocator,
        \\script "bad-ref" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        sig = rf { payload = "x" }
        \\        rf { payload = sig. }
        \\    end
        \\end
    ));
}

test "rejects payload values that are neither strings nor references" {
    try std.testing.expectError(error.InvalidOptionValue, parse(std.testing.allocator,
        \\script "bad-payload" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        rf { payload = 42 }
        \\    end
        \\end
    ));
}

test "rejects a region that is neither a string nor from_policy" {
    try std.testing.expectError(error.UnknownOptionKey, parse(std.testing.allocator,
        \\script "bad-region" do
        \\    use "pack.rf"
        \\    cap tx = subghz.transmit { region = eu }
        \\    step "s" do
        \\        tx { payload = "frame" }
        \\    end
        \\end
    ));
}

test "parses net.http and fail" {
    var source = try parse(std.testing.allocator,
        \\script "http" do
        \\    use "pack.net"
        \\    cap probe = net.http
        \\    step "probe" do
        \\        response = probe { target = "127.0.0.1:8080", path = "/", expect_status = 200 }
        \\        if response.oracle ~= "pass" then
        \\            fail "oracle failed"
        \\        end
        \\    end
        \\end
    );
    defer source.deinit();
    try std.testing.expectEqualStrings("net.http", source.caps[0].verb);
    const fail_stmt = switch (source.steps[0].body[1]) {
        .if_stmt => |branch| branch.then_body[0],
        else => return error.UnexpectedToken,
    };
    switch (fail_stmt) {
        .fail => |message| try std.testing.expectEqualStrings("oracle failed", message),
        else => return error.UnexpectedToken,
    }
}
