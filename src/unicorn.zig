const std = @import("std");
pub const c = @cImport({
    @cInclude("unicorn/unicorn.h");
    @cInclude("unicorn/arm.h");
});

pub const Arch = enum(c_int) {
    Arm = c.UC_ARCH_ARM,
    Arm64,
    Mips,
    X86,
    Ppc,
    Sparc,
    M68k,
};
pub const Mode = struct {
    // generic
    pub const LittleEndian = 0;
    pub const BigEndian = 1 << 30;

    // arm / arm64
    pub const Arm = 0;
    pub const Thumb = 1 << 4;
    pub const Mclass = 1 << 5;
    pub const V8 = 1 << 6;
    pub const ArmBe8 = 1 << 7;

    // arm (32bit)
    pub const Arm926 = 1 << 7;
    pub const Arm946 = 1 << 8;
    pub const Arm1176 = 1 << 9;

    // TODO mips

    // x86 / x64
    pub const Bits16 = 1 << 1;
    pub const Bits32 = 1 << 2;
    pub const Bits64 = 1 << 3;

    // TODO ppc
    // TODO sparc
    // TODO riscv
};
pub const Prot = struct {
    pub const None = 0;
    pub const Read = 1;
    pub const Write = 2;
    pub const Exec = 4;
    pub const All = Read | Write | Exec;
};
pub const Error = error{
    NoMem,
    Arch,
    Handle,
    Mode,
    Version,
    ReadUnmapped,
    WriteUnmapped,
    FetchUnmapped,
    Hook,
    InsnInvalid,
    Map,
    WriteProt,
    ReadProt,
    FetchProt,
    Arg,
    ReadUnaligned,
    WriteUnaligned,
    FetchUnaligned,
    HookExist,
    Resource,
    Exception,
    Unexpected,
};
fn translateError(code: c_int) Error!void {
    switch (code) {
        c.UC_ERR_OK => return,
        c.UC_ERR_NOMEM => return error.NoMem,
        c.UC_ERR_ARCH => return error.Arch,
        c.UC_ERR_HANDLE => return error.Handle,
        c.UC_ERR_MODE => return error.Mode,
        c.UC_ERR_VERSION => return error.Version,
        c.UC_ERR_READ_UNMAPPED => return error.ReadUnmapped,
        c.UC_ERR_WRITE_UNMAPPED => return error.WriteUnmapped,
        c.UC_ERR_FETCH_UNMAPPED => return error.FetchUnmapped,
        c.UC_ERR_HOOK => return error.Hook,
        c.UC_ERR_INSN_INVALID => return error.InsnInvalid,
        c.UC_ERR_MAP => return error.Map,
        c.UC_ERR_WRITE_PROT => return error.WriteProt,
        c.UC_ERR_READ_PROT => return error.ReadProt,
        c.UC_ERR_FETCH_PROT => return error.FetchProt,
        c.UC_ERR_ARG => return error.Arg,
        c.UC_ERR_READ_UNALIGNED => return error.ReadUnaligned,
        c.UC_ERR_WRITE_UNALIGNED => return error.WriteUnaligned,
        c.UC_ERR_FETCH_UNALIGNED => return error.FetchUnaligned,
        c.UC_ERR_HOOK_EXIST => return error.HookExist,
        c.UC_ERR_RESOURCE => return error.Resource,
        c.UC_ERR_EXCEPTION => return error.Exception,
        else => unreachable,
    }
}
pub const OpenError = error{
    NoMem,
    Arch,
    Mode,
};
pub const Engine = opaque {
    const Self = @This();
    extern fn uc_open(c_int, c_int, **Engine) c_int;
    pub fn open(arch: Arch, mode: c_int) OpenError!*Self {
        var uc: *Engine = undefined;
        const res = uc_open(@enumToInt(arch), mode, &uc);
        switch (res) {
            c.UC_ERR_OK => return uc,
            c.UC_ERR_NOMEM => return error.NoMem,
            c.UC_ERR_ARCH => return error.Arch,
            c.UC_ERR_MODE => return error.Mode,
            else => unreachable,
        }
    }
    extern fn uc_close(*Self) c_int;
    pub fn close(uc: *Self) void {
        const res = uc_close(uc);
        if (res == c.UC_ERR_OK)
            return;
        unreachable;
    }
    extern fn uc_mem_map(*Self, u64, usize, u32) c_int;
    pub fn memMap(self: *Self, address: u64, size: usize, perms: u32) Error!void {
        const res = uc_mem_map(self, address, size, perms);
        return translateError(res);
    }
    extern fn uc_mem_write(*Self, u64, *const anyopaque, usize) c_int;
    pub fn memWrite(self: *Self, address: u64, data: []const u8) Error!void {
        const res = uc_mem_write(self, address, data.ptr, data.len);
        return translateError(res);
    }
    extern fn uc_mem_read(*Self, u64, *anyopaque, usize) c_int;
    pub fn memRead(self: *Self, address: u64, buff: []u8) Error!void {
        const res = uc_mem_read(self, address, buff.ptr, buff.len);
        return translateError(res);
    }
    extern fn uc_reg_write(*Self, c_int, *const anyopaque) c_int;
    pub fn regWrite(self: *Self, regid: c_int, value: anytype) Error!void {
        const res = uc_reg_write(self, regid, &value);
        return translateError(res);
    }
    extern fn uc_reg_read(*Self, c_int, *anyopaque) c_int;
    pub fn regRead(self: *Self, regid: c_int, comptime T: type) Error!T {
        var value: T = undefined;
        const res = uc_reg_read(self, regid, &value);
        try translateError(res);
        return value;
    }
    const CbHookMem = *const fn (*Self, c_int, u64, c_int, u64, ?*anyopaque) callconv(.C) bool;
    pub const CbMmioRead = *const fn (*Self, u64, c_uint, ?*anyopaque) callconv(.C) u64;
    pub const CbMmioWrite = *const fn (*Self, u64, c_uint, u64, ?*anyopaque) callconv(.C) void;
    extern fn uc_mmio_map(*Self, u64, u64, CbMmioRead, ?*anyopaque, CbMmioWrite, ?*anyopaque) c_int;
    pub fn mmioMap(self: *Self, address: u64, size: u64, read_cb: CbMmioRead, user_data_read: ?*anyopaque, write_cb: CbMmioWrite, user_data_write: ?*anyopaque) Error!void {
        const res = uc_mmio_map(self, address, size, read_cb, user_data_read, write_cb, user_data_write);
        return translateError(res);
    }
    const Hook = usize;
    extern fn uc_emu_start(*Self, u64, u64, u64, usize) c_int;
    pub fn emuStart(self: *Self, begin: u64, until: u64, timeout: u64, count: usize) Error!void {
        const res = uc_emu_start(self, begin, until, timeout, count);
        return translateError(res);
    }
    extern fn uc_emu_stop(*Self) c_int;
    pub fn emuStop(self: *Self) Error!void {
        const res = uc_emu_stop(self);
        return translateError(res);
    }
    extern fn uc_hook_add(*Self, *Hook, c_int, *const anyopaque, ?*anyopaque, u64, u64, ...) c_int;
    pub fn hookAddMem(self: *Self, cb: CbHookMem, user_data: ?*anyopaque, begin: u64, end: u64) Error!Hook {
        var hook: Hook = undefined;
        const res = uc_hook_add(
            self,
            &hook,
            c.UC_HOOK_MEM_READ_UNMAPPED | c.UC_HOOK_MEM_WRITE_UNMAPPED | c.UC_HOOK_MEM_FETCH_UNMAPPED | c.UC_HOOK_MEM_READ_PROT | c.UC_HOOK_MEM_WRITE_PROT | c.UC_HOOK_MEM_FETCH_PROT,
            cb,
            user_data,
            begin,
            end,
        );
        try translateError(res);
        return hook;
    }
};
