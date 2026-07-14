// ============================================================
// cs2_memory.cpp — CS2 游戏内存读写实现
// ============================================================

#include "cs2_memory.h"
#include <cmath>

namespace cs2 {

Memory& Memory::Instance() {
    static Memory inst;
    return inst;
}

bool Memory::ResolveModules() {
    auto& engine = stealth::StealthEngine::Instance();
    HANDLE hProc = engine.GetProcessHandle();
    if (!hProc) return false;

    auto modules = stealth::StealthProcess::GetProcessModules(hProc);
    for (auto& mod : modules) {
        if (mod.name == L"client.dll") {
            m_clientBase = mod.baseAddress;
        } else if (mod.name == L"engine2.dll") {
            m_engineBase = mod.baseAddress;
        }
    }
    return m_clientBase != 0;
}

bool Memory::Initialize(const Offsets& offsets) {
    m_offsets = offsets;
    m_hProcess = stealth::StealthEngine::Instance().GetProcessHandle();
    return m_hProcess && ResolveModules();
}

uintptr_t Memory::ClientBase()  { return m_clientBase; }
uintptr_t Memory::EngineBase()  { return m_engineBase; }

uintptr_t Memory::EntityList() {
    return Read<uintptr_t>(m_clientBase + m_offsets.dwEntityList);
}

uintptr_t Memory::LocalPlayerController() {
    return Read<uintptr_t>(m_clientBase + m_offsets.dwLocalPlayerPawn);
}

uintptr_t Memory::LocalPlayerPawn() {
    uintptr_t controller = LocalPlayerController();
    if (!controller) return 0;
    uintptr_t pawnHandle = Read<uint32_t>(controller + m_offsets.m_hPlayerPawn);
    if (!pawnHandle || pawnHandle == 0xFFFFFFFF) return 0;

    uintptr_t listEntry = Read<uintptr_t>(EntityList() + 8 * ((pawnHandle & 0x7FFF) >> 9) + 16);
    if (!listEntry) return 0;
    return Read<uintptr_t>(listEntry + 120 * (pawnHandle & 0x1FF));
}

ViewMatrix Memory::GetViewMatrix() {
    // View matrix 不需要频繁更新, 缓存100ms
    DWORD now = GetTickCount();
    if (now - m_lastMatrixUpdate > 100 || !m_lastMatrixUpdate) {
        m_lastMatrixUpdate = now;
        uintptr_t matrixAddr = m_clientBase + m_offsets.dwViewMatrix;
        // 通过规避引擎 syscall 层读取, 避免被 EAC Hook 检测
        if (!stealth::StealthEngine::Instance().ReadBytes(matrixAddr,
                                &m_viewMatrix, sizeof(m_viewMatrix))) {
            memset(&m_viewMatrix, 0, sizeof(m_viewMatrix));
        }
    }
    return m_viewMatrix;
}

bool Memory::WorldToScreen(const Vector3& world, Vector2& screen) {
    ViewMatrix vm = GetViewMatrix();
    float w = vm.m[3][0] * world.x + vm.m[3][1] * world.y + vm.m[3][2] * world.z + vm.m[3][3];
    if (w < 0.001f) return false;

    float invW = 1.0f / w;
    float x = vm.m[0][0] * world.x + vm.m[0][1] * world.y + vm.m[0][2] * world.z + vm.m[0][3];
    float y = vm.m[1][0] * world.x + vm.m[1][1] * world.y + vm.m[1][2] * world.z + vm.m[1][3];

    // 获取屏幕大小
    int screenWidth  = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    screen.x = (screenWidth  / 2.0f) + (screenWidth  / 2.0f) * x * invW;
    screen.y = (screenHeight / 2.0f) - (screenHeight / 2.0f) * y * invW;

    return (screen.x > 0 && screen.x < screenWidth &&
            screen.y > 0 && screen.y < screenHeight);
}

Vector3 Memory::GetBonePosition(uintptr_t pawn, BoneIndex bone) {
    // 简化版: 使用 viewOffset + 高度估算骨骼位置
    // 完整骨骼系统需要读取 bone matrix, 这里用近似值
    Vector3 origin = Read<Vector3>(pawn + 0x1224); // m_vOldOrigin
    int health = Read<int>(pawn + m_offsets.m_iHealth);

    // 玩家模型高度约 72 单位; 头部在 origin + viewOffset + (0,0,~10)
    Vector3 headOffset;
    switch (bone) {
        case BoneIndex::Head:     headOffset = {0, 0, 72.0f}; break;
        case BoneIndex::Neck:     headOffset = {0, 0, 67.0f}; break;
        case BoneIndex::Chest:    headOffset = {0, 0, 64.0f}; break;
        case BoneIndex::Stomach:  headOffset = {0, 0, 56.0f}; break;
        case BoneIndex::Pelvis:   headOffset = {0, 0, 44.0f}; break;
        default:                  headOffset = {0, 0, 64.0f}; break;
    }

    return {origin.x + headOffset.x, origin.y + headOffset.y, origin.z + headOffset.z};
}

std::vector<Entity> Memory::GetAllPlayers(bool onlyAlive) {
    std::vector<Entity> result;
    uintptr_t localPawn = LocalPlayerPawn();
    int localTeam = -1;
    if (localPawn) {
        localTeam = Read<int>(localPawn + m_offsets.m_iTeamNum);
    }

    ViewMatrix vm = GetViewMatrix();

    // 获取实体列表 (单次批量读取链表头部以减少 syscall 数量)
    uintptr_t elBase = EntityList();
    if (!elBase) return result;

    // CS2 实体列表: 最大64实体
    for (int i = 1; i < 64; i++) {
        uintptr_t listEntry = Read<uintptr_t>(elBase + 8 * ((i & 0x7FFF) >> 9) + 16);
        if (!listEntry) continue;

        uintptr_t controller = Read<uintptr_t>(listEntry + 120 * (i & 0x1FF));
        if (!controller) continue;

        if (controller == LocalPlayerController()) continue;

        uint32_t pawnHandle = Read<uint32_t>(controller + m_offsets.m_hPlayerPawn);
        if (!pawnHandle || pawnHandle == 0xFFFFFFFF) continue;

        uintptr_t listEntry2 = Read<uintptr_t>(elBase + 8 * ((pawnHandle & 0x7FFF) >> 9) + 16);
        if (!listEntry2) continue;

        uintptr_t pawn = Read<uintptr_t>(listEntry2 + 120 * (pawnHandle & 0x1FF));
        if (!pawn) continue;

        Entity ent;
        ent.address  = pawn;
        ent.index    = i;

        // === 批量读取 Pawn 属性 (减少 syscall 次数) ===
        // 读取 pawn 基础属性区域 (0x310-0x3D0, 覆盖 health/team/lifeState 等)
        // 单次 syscall 替代 3+ 次独立 Read()
        uint8_t pawnBuf[256] = {};
        stealth::StealthEngine::Instance().ReadBytes(pawn + offsetof_PawnCore, pawnBuf, sizeof(pawnBuf));

        // 解析本地 (无 syscall)
        ent.health    = *(int*)(pawnBuf + (m_offsets.m_iHealth - offsetof_PawnCore));
        ent.team      = *(int*)(pawnBuf + (m_offsets.m_iTeamNum - offsetof_PawnCore));
        ent.lifeState = *(int*)(pawnBuf + (m_offsets.m_lifeState - offsetof_PawnCore));

        if (ent.health <= 0 || ent.health > 100 || ent.lifeState != 0) {
            if (onlyAlive) continue;
        }

        if (onlyAlive && localTeam >= 0 && ent.team == localTeam) continue;

        // === 批量读取位置数据 (origin + viewOffset, 24 bytes) ===
        struct { float x, y, z, x2, y2, z2; } posBuf;
        stealth::StealthEngine::Instance().ReadBytes(pawn + m_offsets.m_vecOrigin, &posBuf, sizeof(posBuf));

        ent.origin     = {posBuf.x,  posBuf.y,  posBuf.z};
        ent.viewOffset = {posBuf.x2, posBuf.y2, posBuf.z2};
        ent.headPos    = {ent.origin.x, ent.origin.y, ent.origin.z + ent.viewOffset.z + 10.0f};

        // 休眠/武器/盔甲状态 (非连续字段, 分别读取)
        ent.isDormant  = Read<uint8_t>(pawn + m_offsets.m_bDormant) != 0;
        ent.isScoped   = Read<uint8_t>(pawn + m_offsets.m_bIsScoped) != 0;
        ent.armor      = Read<int>(pawn + m_offsets.m_ArmorValue);
        ent.hasDefuser = Read<uint8_t>(pawn + m_offsets.m_bHasDefuser) != 0;
        ent.hasHelmet  = Read<uint8_t>(pawn + m_offsets.m_bHasHelmet) != 0;
        ent.isAlive    = true;

        // 武器 (偏移 0x1388 距离核心区太远, 单独读取)
        uintptr_t weaponHandle = Read<uint32_t>(pawn + m_offsets.m_pClippingWeapon);
        if (weaponHandle && weaponHandle != 0xFFFFFFFF) {
            uintptr_t wepListEntry = Read<uintptr_t>(elBase + 8 * ((weaponHandle & 0x7FFF) >> 9) + 16);
            if (wepListEntry) {
                ent.weaponAddress = Read<uintptr_t>(wepListEntry + 120 * (weaponHandle & 0x1FF));
                if (ent.weaponAddress) {
                    uintptr_t attr = Read<uintptr_t>(ent.weaponAddress + m_offsets.m_AttributeManager);
                    uintptr_t item = Read<uintptr_t>(attr + m_offsets.m_Item);
                    ent.weaponId = Read<short>(item + m_offsets.m_ItemDefIndex);
                }
            }
        }

        // 名称
        ent.name = ReadString(controller + m_offsets.m_sSanitizedPlayerName, 64);

        // 距离
        if (localPawn) {
            Vector3 localOrigin = Read<Vector3>(localPawn + m_offsets.m_vecOrigin);
            ent.distance = ent.origin.Distance(localOrigin) * 0.0254f;
        }

        // 屏幕投影
        WorldToScreen(ent.origin, ent.screenPos);

        Vector3 headWorld = {ent.origin.x, ent.origin.y, ent.origin.z + 72.0f};
        Vector3 feetWorld = {ent.origin.x, ent.origin.y, ent.origin.z};
        WorldToScreen(headWorld, ent.screenHead);
        WorldToScreen(feetWorld, ent.screenFeet);

        ent.boxHeight = ent.screenFeet.y - ent.screenHead.y;
        if (ent.boxHeight < 5.0f) ent.boxHeight = 5.0f;
        ent.boxWidth  = ent.boxHeight * 0.4f;
        if (ent.boxWidth  < 2.0f) ent.boxWidth  = 2.0f;

        if (ent.isDormant) continue;

        result.push_back(ent);
    }

    return result;
}

Entity Memory::GetLocalPlayer() {
    Entity local;
    uintptr_t controller = LocalPlayerController();
    uintptr_t pawn       = LocalPlayerPawn();
    if (!pawn) return local;

    local.address  = pawn;
    local.team     = Read<int>(pawn + m_offsets.m_iTeamNum);
    local.health   = Read<int>(pawn + m_offsets.m_iHealth);
    local.origin   = Read<Vector3>(pawn + m_offsets.m_vecOrigin);
    local.viewOffset = Read<Vector3>(pawn + m_offsets.m_vecViewOffset);
    local.isAlive  = (local.health > 0);
    local.armor    = Read<int>(pawn + m_offsets.m_ArmorValue);
    local.hasHelmet = Read<bool>(pawn + m_offsets.m_bHasHelmet);
    local.isScoped  = Read<bool>(pawn + m_offsets.m_bIsScoped);

    if (controller) {
        local.name = ReadString(controller + m_offsets.m_sSanitizedPlayerName, 64);
    }

    return local;
}

std::string Memory::ReadString(uintptr_t addr, size_t maxLen) {
    if (!addr) return "";
    size_t readLen = (maxLen < 255 ? maxLen : 255);
    char buf[256] = {};
    // 通过规避引擎 syscall 层读取, 避免 EAC Hook 检测
    bool ok = stealth::StealthEngine::Instance().ReadBytes(addr, buf, readLen);
    return ok ? std::string(buf) : "";
}

} // namespace cs2
