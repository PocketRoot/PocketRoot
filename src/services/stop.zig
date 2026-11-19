//! Shared cooperative stop check passed into long-running transports.

pub const Check = struct {
    context: *anyopaque,
    isStopped: *const fn (*anyopaque) bool,
};
