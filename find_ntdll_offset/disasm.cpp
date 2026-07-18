// disasm.cpp - 反汇编 ntdll!RtlDeactivateActivationContext 函数在偏移 +0x5A2 附近的代码
// 目的: 确定什么指令导致 ACCESS_VIOLATION 崩溃
//
// 编译: C:\msys64\mingw64\bin\g++.exe -std=c++20 -O2 -o disasm.exe disasm.cpp -lpsapi
//
// Windows 激活上下文栈结构 (ACTIVATION_CONTEXT_STACK):
//   +0x00 Flags
//   +0x08 NextCookieSequenceNumber
//   +0x0C ActiveFrame (PRTL_ACTIVATION_CONTEXT_STACK_FRAME)
//   +0x10 FrameListCache (LIST_ENTRY: ActiveFrame 之外的链表)
//   +0x20 ...
//
// RTL_ACTIVATION_CONTEXT_STACK_FRAME:
//   +0x00 Previous           (PRTL_ACTIVATION_CONTEXT_STACK_FRAME)
//   +0x08 ActivationContext  (PACTIVATION_CONTEXT)
//   +0x10 Flags
//
// ACTIVATION_CONTEXT (部分字段):
//   +0x00 ReferenceCount / Tag
//   +0x08 ...
//   +0x18 ... (可能包含 Invalid 标志或链表)

#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "psapi.lib")

// ---- 通用寄存器名 (x64) ----
static const char* kReg64[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10","r11","r12","r13","r14","r15"
};

// ---- 小工具 ----
static bool IsRexPrefix(uint8_t b) { return (b & 0xF0) == 0x40; }

// 解析 ModRM 的内存操作数, 返回指令长度(含可能的后置字节)。
static int DecodeModRM(const uint8_t* p,
                      int   prefixLen,
                      const char*& regField,
                      char*   memBuf,
                      size_t  memBufSz)
{
    uint8_t modrm = p[0];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm  = modrm & 7;

    int regIdx = reg;
    (void)prefixLen;
    regField = kReg64[regIdx & 15];

    int extra = 1;  // ModRM 本身

    if (mod == 3) {
        snprintf(memBuf, memBufSz, "%s", kReg64[rm]);
        return extra;
    }

    // SIB?
    if (mod != 3 && rm == 4) {
        uint8_t sib = p[1];
        int scale = 1 << ((sib >> 6) & 3);
        int index = (sib >> 3) & 7;
        int base  = sib & 7;
        extra++;
        if (mod == 0 && base == 5) {
            int32_t disp = *(int32_t*)&p[2];
            extra += 4;
            snprintf(memBuf, memBufSz, "[0x%X + %s*%d]", (unsigned)disp, kReg64[index], scale);
        } else if (mod == 0) {
            snprintf(memBuf, memBufSz, "[%s + %s*%d]", kReg64[base], kReg64[index], scale);
        } else if (mod == 1) {
            int8_t disp = *(int8_t*)&p[1 + 1];
            extra += 1;
            snprintf(memBuf, memBufSz, "[%s + %s*%d + 0x%X]", kReg64[base], kReg64[index], scale, (unsigned)(uint8_t)disp);
        } else {
            int32_t disp = *(int32_t*)&p[1 + 1];
            extra += 4;
            snprintf(memBuf, memBufSz, "[%s + %s*%d + 0x%X]", kReg64[base], kReg64[index], scale, (unsigned)disp);
        }
        return extra;
    }

    // 无 SIB
    if (mod == 0) {
        if (rm == 5) {
            int32_t disp = *(int32_t*)&p[1];
            extra += 4;
            snprintf(memBuf, memBufSz, "[rip+0x%X]", (unsigned)disp);
        } else {
            snprintf(memBuf, memBufSz, "[%s]", kReg64[rm]);
        }
    } else if (mod == 1) {
        int8_t disp = *(int8_t*)&p[1];
        extra += 1;
        snprintf(memBuf, memBufSz, "[%s + 0x%02X]", kReg64[rm], (unsigned)(uint8_t)disp);
    } else {
        int32_t disp = *(int32_t*)&p[1];
        extra += 4;
        snprintf(memBuf, memBufSz, "[%s + 0x%X]", kReg64[rm], (unsigned)disp);
    }
    return extra;
}

// 轻量级反汇编, 仅识别与 ACCESS_VIOLATION 相关的模式。
static int LightDisasm(const uint8_t* p, size_t avail, char* outBuf, size_t outBufSz)
{
    if (avail == 0) return 0;
    const uint8_t* start = p;
    int rexLen = 0;
    bool hasLock = false;
    while (p - start < 4 && avail > (size_t)(p - start) + 1) {
        uint8_t b = *p;
        if (IsRexPrefix(b)) { rexLen++; p++; }
        else if (b == 0xF0) { hasLock = true; p++; }
        else if (b == 0xF2) { p++; }
        else if (b == 0xF3) { p++; }
        else if (b == 0x66) { p++; }
        else break;
    }

    uint8_t op = *p;
    const char* lockStr = hasLock ? "lock " : "";
    size_t need2 = (size_t)(p - start) + 2;
    size_t need3 = (size_t)(p - start) + 3;
    size_t need6 = (size_t)(p - start) + 6;

    // ---- FF /2 = CALL r/m64 (间接调用) ----
    if (op == 0xFF && avail >= need2) {
        uint8_t modrm = p[1];
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t mod = (modrm >> 6) & 3;
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        if (reg == 2) {
            if (mod == 3) snprintf(outBuf, outBufSz, "%scall %s", lockStr, memBuf);
            else snprintf(outBuf, outBufSz, "%scall qword ptr %s  ; <-- INDIRECT CALL (dereferences pointer)", lockStr, memBuf);
            return totalLen;
        } else if (reg == 4) {
            snprintf(outBuf, outBufSz, "%sjmp qword ptr %s", lockStr, memBuf);
            return totalLen;
        } else if (reg == 6) {
            snprintf(outBuf, outBufSz, "%spush %s", lockStr, memBuf);
            return totalLen;
        }
    }

    // ---- 8B = MOV r64, r/m64 ----
    if (op == 0x8B && avail >= need2) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        uint8_t modrm = p[1];
        uint8_t mod = (modrm >> 6) & 3;
        if (mod != 3) snprintf(outBuf, outBufSz, "mov %s, %s  ; <-- LOAD (dereferences pointer)", regName, memBuf);
        else snprintf(outBuf, outBufSz, "mov %s, %s", regName, memBuf);
        return totalLen;
    }

    // ---- 89 = MOV r/m64, r64 (写) ----
    if (op == 0x89 && avail >= need2) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        uint8_t modrm = p[1];
        uint8_t mod = (modrm >> 6) & 3;
        if (mod != 3) snprintf(outBuf, outBufSz, "mov %s, %s  ; <-- STORE (dereferences pointer)", memBuf, regName);
        else snprintf(outBuf, outBufSz, "mov %s, %s", memBuf, regName);
        return totalLen;
    }

    // ---- 0F B0 = CMPXCHG r/m, r (原子) ----
    if (op == 0x0F && avail >= need3 && p[1] == 0xB0) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 2, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + 1 + modrmLen;
        snprintf(outBuf, outBufSz, "%scmpxchg %s, %s  ; <-- ATOMIC (dereferences pointer)", lockStr, memBuf, regName);
        return totalLen;
    }

    // ---- 0F C1 = XADD r/m, r (原子) ----
    if (op == 0x0F && avail >= need3 && p[1] == 0xC1) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 2, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + 1 + modrmLen;
        snprintf(outBuf, outBufSz, "%sxadd %s, %s  ; <-- ATOMIC (dereferences pointer)", lockStr, memBuf, regName);
        return totalLen;
    }

    // ---- 0F 0B = UD2, 0F B9 = UD1 ----
    if (op == 0x0F && avail >= need2 && (p[1] == 0x0B || p[1] == 0xB9)) {
        snprintf(outBuf, outBufSz, "ud2/ud1  ; <-- DEFINITE TRAP");
        return (int)(p - start) + 2;
    }

    // ---- 0F 05 = SYSCALL ----
    if (op == 0x0F && avail >= need2 && p[1] == 0x05) {
        snprintf(outBuf, outBufSz, "syscall");
        return (int)(p - start) + 2;
    }

    // ---- 50-57 = PUSH r64, 58-5F = POP r64 ----
    if (op >= 0x50 && op <= 0x5F) {
        int idx = (op - 0x50) & 7;
        const char* opName = (op < 0x58) ? "push" : "pop";
        snprintf(outBuf, outBufSz, "%s %s", opName, kReg64[idx]);
        return (int)(p - start) + 1;
    }

    // ---- 83 /r ib, 81 /r id ----
    if ((op == 0x83 || op == 0x81) && avail >= need2) {
        uint8_t modrm = p[1];
        uint8_t reg = (modrm >> 3) & 7;
        const char* ops[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int immLen = (op == 0x81) ? 4 : 1;
        int totalLen = (int)(p - start) + modrmLen + immLen;
        uint8_t mod = (modrm >> 6) & 3;
        if (op == 0x81) {
            int32_t imm = *(int32_t*)&p[1 + (modrmLen - 1)];
            if (mod != 3) snprintf(outBuf, outBufSz, "%s %s, 0x%X  ; <-- MEMORY OPERAND (dereferences pointer)", ops[reg], memBuf, (unsigned)imm);
            else snprintf(outBuf, outBufSz, "%s %s, 0x%X", ops[reg], memBuf, (unsigned)imm);
        } else {
            int8_t imm = *(int8_t*)&p[1 + (modrmLen - 1)];
            if (mod != 3) snprintf(outBuf, outBufSz, "%s %s, 0x%X  ; <-- MEMORY OPERAND (dereferences pointer)", ops[reg], memBuf, (unsigned)(uint8_t)imm);
            else snprintf(outBuf, outBufSz, "%s %s, 0x%X", ops[reg], memBuf, (unsigned)(uint8_t)imm);
        }
        return totalLen;
    }

    // ---- 85 /r = TEST r/m64, r64 ----
    if ((op == 0x85 || op == 0xF7) && avail >= need2) {
        uint8_t modrm = p[1];
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        uint8_t mod = (modrm >> 6) & 3;
        const char* opName = (op == 0x85) ? "test" : "f7";
        if (mod != 3 && op == 0x85) snprintf(outBuf, outBufSz, "test %s, %s  ; <-- NULL CHECK (dereferences pointer)", memBuf, regName);
        else if (mod != 3 && op == 0xF7) snprintf(outBuf, outBufSz, "%s %s, ...  ; <-- MEMORY OPERAND", opName, memBuf);
        else snprintf(outBuf, outBufSz, "%s %s, %s", opName, memBuf, regName);
        return totalLen;
    }

    // ---- 8D /r = LEA r64, m ----
    if (op == 0x8D && avail >= need2) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        snprintf(outBuf, outBufSz, "lea %s, %s", regName, memBuf);
        return totalLen;
    }

    // ---- 0F 80-8F = Jcc rel32 ----
    if (op == 0x0F && avail >= need6 && (p[1] >= 0x80 && p[1] <= 0x8F)) {
        int32_t rel = *(int32_t*)&p[2];
        const char* cc[] = {"jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"};
        snprintf(outBuf, outBufSz, "%s rel32 (0x%X)", cc[p[1] - 0x80], (unsigned)rel);
        return (int)(p - start) + 6;
    }
    if (op >= 0x70 && op <= 0x7F) {
        int8_t rel = *(int8_t*)&p[1];
        const char* cc[] = {"jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"};
        snprintf(outBuf, outBufSz, "%s rel8 (0x%X)", cc[op - 0x70], (unsigned)(uint8_t)rel);
        return (int)(p - start) + 2;
    }

    // ---- E8 = CALL rel32, E9 = JMP rel32, EB = JMP rel8 ----
    if (op == 0xE8) {
        int32_t rel = *(int32_t*)&p[1];
        snprintf(outBuf, outBufSz, "call rel32 (0x%X)", (unsigned)rel);
        return (int)(p - start) + 5;
    }
    if (op == 0xE9) {
        int32_t rel = *(int32_t*)&p[1];
        snprintf(outBuf, outBufSz, "jmp rel32 (0x%X)", (unsigned)rel);
        return (int)(p - start) + 5;
    }
    if (op == 0xEB) {
        int8_t rel = *(int8_t*)&p[1];
        snprintf(outBuf, outBufSz, "jmp rel8 (0x%X)", (unsigned)(uint8_t)rel);
        return (int)(p - start) + 2;
    }

    // ---- C3 = RET, C2 = RET imm16 ----
    if (op == 0xC3) { snprintf(outBuf, outBufSz, "ret"); return (int)(p - start) + 1; }
    if (op == 0xC2) { uint16_t imm = *(uint16_t*)&p[1]; snprintf(outBuf, outBufSz, "ret 0x%X", imm); return (int)(p - start) + 3; }

    // ---- 90 = NOP ----
    if (op == 0x90) { snprintf(outBuf, outBufSz, "nop"); return (int)(p - start) + 1; }

    // ---- 3B /r = CMP r64, r/m64 ----
    if (op == 0x3B && avail >= need2) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        uint8_t modrm = p[1];
        uint8_t mod = (modrm >> 6) & 3;
        if (mod != 3) snprintf(outBuf, outBufSz, "cmp %s, %s  ; <-- LOAD (dereferences pointer)", regName, memBuf);
        else snprintf(outBuf, outBufSz, "cmp %s, %s", regName, memBuf);
        return totalLen;
    }

    // ---- 39 /r = CMP r/m64, r64 ----
    if (op == 0x39 && avail >= need2) {
        const char* regName;
        char memBuf[64];
        int modrmLen = DecodeModRM(p + 1, rexLen, regName, memBuf, sizeof(memBuf));
        int totalLen = (int)(p - start) + modrmLen;
        uint8_t modrm = p[1];
        uint8_t mod = (modrm >> 6) & 3;
        if (mod != 3) snprintf(outBuf, outBufSz, "cmp %s, %s  ; <-- MEMORY OPERAND (dereferences pointer)", memBuf, regName);
        else snprintf(outBuf, outBufSz, "cmp %s, %s", memBuf, regName);
        return totalLen;
    }

    // 未识别
    snprintf(outBuf, outBufSz, ".byte 0x%02X  ; (unrecognized)", op);
    return (int)(p - start) + 1;
}

// 打印一段内存的 hex dump (16 字节/行, 标注偏移)
static void HexDump(const uint8_t* base, size_t funcOffset, size_t length)
{
    for (size_t i = 0; i < length; i += 16) {
        printf("+0x%03zX: ", funcOffset + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) printf("%02X ", base[i + j]);
            else                printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                uint8_t c = base[i + j];
                putchar((c >= 0x20 && c < 0x7F) ? c : '.');
            } else {
                putchar(' ');
            }
        }
        printf("|\n");
    }
}

int main()
{
    // ---------- 1. 加载 ntdll.dll ----------
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[ERR] Failed to load ntdll.dll\n");
        return 1;
    }
    printf("=== Step 1: Loaded ntdll.dll ===\n");
    printf("  ntdll base = 0x%p\n", (void*)hNtdll);

    // ---------- 2. 找到 RtlDeactivateActivationContext ----------
    FARPROC pfn = GetProcAddress(hNtdll, "RtlDeactivateActivationContext");
    if (!pfn) {
        printf("[ERR] Failed to resolve RtlDeactivateActivationContext\n");
        return 1;
    }
    uint8_t* pFunc = (uint8_t*)pfn;
    DWORD funcRva = (DWORD)((uintptr_t)pFunc - (uintptr_t)hNtdll);

    printf("\n=== Step 2: Resolved RtlDeactivateActivationContext ===\n");
    printf("  VA           = 0x%p\n", (void*)pfn);
    printf("  RVA          = 0x%X\n", funcRva);

    // ---------- 3. 获取函数大小 (RtlLookupFunctionEntry) ----------
    DWORD64 imgBase2 = 0;
    PRUNTIME_FUNCTION pRT = RtlLookupFunctionEntry((DWORD64)pfn, &imgBase2, NULL);
    DWORD funcSize = 0;
    if (pRT) {
        funcSize = pRT->EndAddress - pRT->BeginAddress;
        printf("\n=== Step 3: Function Size (via RtlLookupFunctionEntry) ===\n");
        printf("  ImageBase     = 0x%llX\n", (unsigned long long)imgBase2);
        printf("  BeginAddress  = 0x%X\n", pRT->BeginAddress);
        printf("  EndAddress    = 0x%X\n", pRT->EndAddress);
        printf("  Function size = 0x%X (%u bytes)\n", funcSize, funcSize);
    } else {
        printf("\n=== Step 3: RtlLookupFunctionEntry returned NULL ===\n");
    }

    MODULEINFO mi = {};
    if (GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi))) {
        printf("  ntdll SizeOfImage = 0x%X\n", mi.SizeOfImage);
    }

    if (funcSize && funcSize < 0x5C0) {
        printf("\n[WARN] Function size 0x%X is smaller than target offset 0x5A2!\n", funcSize);
        printf("       The +0x5A2 offset may be OUTSIDE this function.\n");
    }

    // ---------- 4. 打印函数序言 (前 64 字节) ----------
    printf("\n=== Step 4: Function Prologue (first 64 bytes) ===\n");
    HexDump(pFunc, 0, 64);

    printf("\n--- Disasm of prologue ---\n");
    {
        size_t off = 0;
        int count = 0;
        while (off < 64 && count < 20) {
            char buf[160];
            int len = LightDisasm(pFunc + off, 64 - off, buf, sizeof(buf));
            if (len <= 0) { printf("+0x%03zX: <decode fail>\n", off); break; }
            printf("+0x%03zX: %s\n", off, buf);
            off += len;
            count++;
        }
    }

    // ---------- 5. 打印 +0x580 到 +0x5C0 (覆盖 +0x5A2 前后 32 字节) ----------
    const size_t kStartOff = 0x580;
    const size_t kEndOff   = 0x5C0;
    const size_t kLen      = kEndOff - kStartOff;
    printf("\n=== Step 5: Hex dump [+0x580, +0x5C0)  (covers +/-32 bytes around +0x5A2) ===\n");
    HexDump(pFunc + kStartOff, kStartOff, kLen);

    // ---------- 6. 特别标记 +0x5A2 处的字节 ----------
    printf("\n=== Step 6: Bytes at offset +0x5A2 ===\n");
    printf("  Raw bytes: ");
    for (int i = 0; i < 16; i++) printf("%02X ", pFunc[0x5A2 + i]);
    printf("\n");

    printf("\n--- Focused dump: +0x592 .. +0x5B2 (16 bytes before/after +0x5A2) ---\n");
    HexDump(pFunc + 0x592, 0x592, 0x21);

    // ---------- 7. 轻量反汇编 +0x580 .. +0x5C0 区域 ----------
    printf("\n=== Step 7: Light disassembly [+0x580, +0x5C0) ===\n");
    {
        size_t off = kStartOff;
        int count = 0;
        while (off < kEndOff && count < 60) {
            char buf[160];
            int len = LightDisasm(pFunc + off, kEndOff - off, buf, sizeof(buf));
            if (len <= 0) {
                printf("+0x%03zX: .byte 0x%02X\n", off, pFunc[off]);
                off += 1; count++; continue;
            }
            const char* marker = (off == 0x5A2) ? " <<<--- TARGET OFFSET" :
                                 (off <= 0x5A2 && off + (size_t)len > 0x5A2) ? " <--- contains +0x5A2" : "";
            printf("+0x%03zX: %s%s\n", off, buf, marker);
            off += len;
            count++;
        }
    }

    // ---------- 8. 在 +0x5A2 处单独反汇编一条 ----------
    printf("\n=== Step 8: Decode instruction starting exactly at +0x5A2 ===\n");
    {
        char buf[160];
        int len = LightDisasm(pFunc + 0x5A2, 16, buf, sizeof(buf));
        if (len > 0) {
            printf("  Instruction at +0x5A2 (length=%d): %s\n", len, buf);
            printf("  Bytes: ");
            for (int i = 0; i < len && i < 16; i++) printf("%02X ", pFunc[0x5A2 + i]);
            printf("\n");
        } else {
            printf("  Could not decode instruction at +0x5A2\n");
        }
    }

    // ---------- 9. 分析 +0x5A2 附近的指针解引用模式 ----------
    printf("\n=== Step 9: Pattern analysis around +0x5A2 ===\n");
    printf("  Bytes +0x59A..+0x5AA: ");
    for (int i = 0; i < 16; i++) printf("%02X ", pFunc[0x59A + i]);
    printf("\n");

    uint8_t b0 = pFunc[0x5A2];
    uint8_t b1 = pFunc[0x5A3];
    uint8_t b2 = pFunc[0x5A4];
    uint8_t b3 = pFunc[0x5A5];

    printf("\n  Pattern checks at +0x5A2:\n");

    // REX.W + MOV r64, [reg+disp]
    if (IsRexPrefix(b0) && b1 == 0x8B) {
        uint8_t modrm = b2;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm  = modrm & 7;
        const char* dst = kReg64[reg];
        const char* srcBase = kReg64[rm];
        if (mod == 1) {
            printf("    [MATCH] mov %s, [%s + 0x%02X]  (REX.W + 8B + ModRM disp8)\n", dst, srcBase, pFunc[0x5A5]);
            printf("            -> LOAD from struct field. Fault addr = *(%s) + 0x%02X\n", srcBase, pFunc[0x5A5]);
        } else if (mod == 2) {
            uint32_t disp = *(uint32_t*)&pFunc[0x5A5];
            printf("    [MATCH] mov %s, [%s + 0x%X]  (REX.W + 8B + ModRM disp32)\n", dst, srcBase, disp);
            printf("            -> LOAD from struct field. Fault addr = *(%s) + 0x%X\n", srcBase, disp);
        } else if (mod == 0 && rm != 4 && rm != 5) {
            printf("    [MATCH] mov %s, [%s]  (REX.W + 8B + ModRM mod0)\n", dst, srcBase);
            printf("            -> LOAD via register. Fault addr = *(%s)\n", srcBase);
        }
    }
    // REX.W + CALL [reg+disp]
    if (IsRexPrefix(b0) && b1 == 0xFF) {
        uint8_t modrm = b2;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm  = modrm & 7;
        if (reg == 2) {
            const char* srcBase = kReg64[rm];
            if (mod == 1) {
                printf("    [MATCH] call qword ptr [%s + 0x%02X]  (REX.W + FF/2 disp8)\n", srcBase, pFunc[0x5A5]);
                printf("            -> INDIRECT CALL via struct field. Fault addr = *(%s) + 0x%02X\n", srcBase, pFunc[0x5A5]);
            } else if (mod == 2) {
                uint32_t disp = *(uint32_t*)&pFunc[0x5A5];
                printf("    [MATCH] call qword ptr [%s + 0x%X]  (REX.W + FF/2 disp32)\n", srcBase, disp);
                printf("            -> INDIRECT CALL via struct field. Fault addr = *(%s) + 0x%X\n", srcBase, disp);
            } else if (mod == 0 && rm != 4 && rm != 5) {
                printf("    [MATCH] call qword ptr [%s]  (REX.W + FF/2 mod0)\n", srcBase);
                printf("            -> INDIRECT CALL. Fault addr = *(%s)\n", srcBase);
            }
        }
    }
    // CMPXCHG (lock 0F B0 /r)
    if ((b0 == 0xF0 && b1 == 0x0F && b2 == 0xB0) ||
        (b0 == 0x0F && b1 == 0xB0)) {
        printf("    [MATCH] cmpxchg (atomic) at +0x5A2\n");
    }
    // LOCK XADD (F0 0F C1)
    if (b0 == 0xF0 && b1 == 0x0F && b2 == 0xC1) {
        printf("    [MATCH] lock xadd (atomic) at +0x5A2\n");
    }

    // FF /2 without REX (call qword ptr [reg+disp])
    if (b0 == 0xFF) {
        uint8_t modrm = b1;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm  = modrm & 7;
        if (reg == 2 && mod != 3) {
            const char* srcBase = kReg64[rm];
            if (mod == 1) {
                printf("    [MATCH] call qword ptr [%s + 0x%02X]  (FF/2 disp8, no REX)\n", srcBase, b3);
                printf("            -> INDIRECT CALL via struct field. Fault addr = *(%s) + 0x%02X\n", srcBase, b3);
            } else if (mod == 2) {
                uint32_t disp = *(uint32_t*)&pFunc[0x5A4];
                printf("    [MATCH] call qword ptr [%s + 0x%X]  (FF/2 disp32, no REX)\n", srcBase, disp);
                printf("            -> INDIRECT CALL via struct field. Fault addr = *(%s) + 0x%X\n", srcBase, disp);
            }
        }
    }

    // 8B without REX (mov r32, [reg+disp]) -- 32-bit load
    if (b0 == 0x8B) {
        uint8_t modrm = b1;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm  = modrm & 7;
        if (mod != 3) {
            const char* dst = kReg64[reg];
            const char* srcBase = kReg64[rm];
            if (mod == 1) {
                printf("    [MATCH] mov %s, [%s + 0x%02X]  (8B disp8, no REX)\n", dst, srcBase, b3);
                printf("            -> LOAD from struct field. Fault addr = *(%s) + 0x%02X\n", srcBase, b3);
            } else if (mod == 2) {
                uint32_t disp = *(uint32_t*)&pFunc[0x5A4];
                printf("    [MATCH] mov %s, [%s + 0x%X]  (8B disp32, no REX)\n", dst, srcBase, disp);
                printf("            -> LOAD from struct field. Fault addr = *(%s) + 0x%X\n", srcBase, disp);
            }
        }
    }


    printf("\n=== Done ===\n");
    return 0;
}
