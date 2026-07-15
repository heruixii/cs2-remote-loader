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
    return Read<uintptr_t>(m_clientBase + m_offsets.dwLocalPlayerController);
}

uintptr_t Memory::LocalPlayerPawn() {
    uintptr_t controller = LocalPlayerController();
    if (!controller) return 0;
    uintptr_t pawnHandle = Read<uint32_t>(controller + m_offsets.m_hPlayerPawn);
    if (!pawnHandle || pawnHandle == 0xFFFFFFFF) return 0;

    uintptr_t el = EntityList();
    if (!el) return 0;
    uintptr_t listEntry = Read<uintptr_t>(el + 8 * ((pawnHandle & 0x7FFF) >> 9) + 16);
    listEntry &= ~0xFULL;  // strip tag bits from entity identity pointer
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

    // 获取屏幕大小 (优先使用 overlay 实际尺寸)
    int screenWidth  = (m_screenWidth  > 0) ? m_screenWidth  : GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = (m_screenHeight > 0) ? m_screenHeight : GetSystemMetrics(SM_CYSCREEN);

    screen.x = (screenWidth  / 2.0f) + (screenWidth  / 2.0f) * x * invW;
    screen.y = (screenHeight / 2.0f) - (screenHeight / 2.0f) * y * invW;

    return (screen.x > 0 && screen.x < screenWidth &&
            screen.y > 0 && screen.y < screenHeight);
}

Vector3 Memory::GetBonePosition(uintptr_t pawn, BoneIndex bone) {
    // 简化版: 使用 viewOffset + 高度估算骨骼位置
    // 完整骨骼系统需要读取 bone matrix, 这里用近似值
    uintptr_t gameSceneNode = Read<uintptr_t>(pawn + m_offsets.m_pGameSceneNode);
    Vector3 origin = {0, 0, 0};
    if (gameSceneNode)
        origin = Read<Vector3>(gameSceneNode + m_offsets.m_vecOrigin);

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

    // 获取实体列表
    uintptr_t elBase = EntityList();
    if (!elBase) return result;

    // 缓存 chunk 0 指针
    uintptr_t chunk0 = Read<uintptr_t>(elBase + 16) & ~0xFULL;
    if (!chunk0) return result;

    constexpr int MAX_ENTRIES = 512;
    constexpr int IDENTITY_STRIDE = 120; // CEntityIdentity size
    constexpr int CHUNK_SIZE = MAX_ENTRIES * IDENTITY_STRIDE; // 61440 bytes

    // 批量读取整个 identity chunk (1次 syscall, 消除每实体独立读取)
    static uint8_t chunkBuf[CHUNK_SIZE] = {};
    stealth::StealthEngine::Instance().ReadBytes(chunk0, chunkBuf, CHUNK_SIZE);

    uintptr_t localController = LocalPlayerController();

    // CS2 实体列表: 遍历整个第一块 (0~511), 本地解析
    // v3.31: 两阶段识别 — 先尝试 Controller→Pawn 链, 失败则尝试直接 Pawn
    for (int i = 1; i < MAX_ENTRIES; i++) {
        uintptr_t entityPtr = *(uintptr_t*)(chunkBuf + i * IDENTITY_STRIDE);
        if (!entityPtr) continue;
        if (entityPtr == localController) continue;

        uintptr_t pawn = 0;
        bool isDirectPawn = false;

        // 阶段1: Controller→Pawn 链 (人类玩家路径)
        uint32_t pawnHandle = Read<uint32_t>(entityPtr + m_offsets.m_hPlayerPawn);
        if (pawnHandle && pawnHandle != 0xFFFFFFFF) {
            uintptr_t listEntry2 = Read<uintptr_t>(elBase + 8 * ((pawnHandle & 0x7FFF) >> 9) + 16);
            if (listEntry2) {
                listEntry2 &= ~0xFULL;  // strip tag bits
                pawn = Read<uintptr_t>(listEntry2 + 120 * (pawnHandle & 0x1FF));
            }
        }

        // 阶段2: 直接 Pawn (Bot/无独立Controller路径, v3.31)
        //         当阶段1失败时, entityPtr 本身可能就是 pawn
        if (!pawn) {
            // 验证: 读取 team 和 health, 如果合法则为 pawn
            uint8_t testBuf[256] = {};
            if (stealth::StealthEngine::Instance().ReadBytes(
                    entityPtr + offsetof_PawnCore, testBuf, sizeof(testBuf))) {
                int testHealth = *(int*)(testBuf + (m_offsets.m_iHealth - offsetof_PawnCore));
                int testTeam   = *(int*)(testBuf + (m_offsets.m_iTeamNum - offsetof_PawnCore));
                int testLife   = *(int*)(testBuf + (m_offsets.m_lifeState - offsetof_PawnCore));
                if (testHealth > 0 && testHealth <= 100 && testLife == 0
                    && (testTeam == 2 || testTeam == 3)) {
                    pawn = entityPtr;
                    isDirectPawn = true;
                }
            }
        }

        if (!pawn) continue;

        Entity ent;
        ent.address  = pawn;
        ent.index    = i;

        // === 批量读取 Pawn 属性 (减少 syscall 次数) ===
        // 读取 pawn 基础属性区域 (0x310-0x3D0, 覆盖 health/team/lifeState 等)
        // 单次 syscall 替代 3+ 次独立 Read()
        uint8_t pawnBuf[256] = {};
        if (!stealth::StealthEngine::Instance().ReadBytes(pawn + offsetof_PawnCore, pawnBuf, sizeof(pawnBuf)))
            continue;

        // 解析本地 (无 syscall)
        ent.health    = *(int*)(pawnBuf + (m_offsets.m_iHealth - offsetof_PawnCore));
        ent.team      = *(int*)(pawnBuf + (m_offsets.m_iTeamNum - offsetof_PawnCore));
        ent.lifeState = *(int*)(pawnBuf + (m_offsets.m_lifeState - offsetof_PawnCore));

        if (ent.health <= 0 || ent.health > 100 || ent.lifeState != 0) {
            if (onlyAlive) continue;
        }

        if (onlyAlive && localTeam >= 0 && ent.team == localTeam) continue;

        // === 读取位置数据 ===
        // m_vecOrigin=0x1224 是 CGameSceneNode 内部的偏移,
        // 必须先解引用 pawn+0x310 获取 gameSceneNode 指针
        uintptr_t gameSceneNode = *(uintptr_t*)(pawnBuf + 0); // pawn+0x310=m_pGameSceneNode
        ent.origin = {0, 0, 0};
        if (gameSceneNode) {
            stealth::StealthEngine::Instance().ReadBytes(gameSceneNode + m_offsets.m_vecOrigin,
                                                          &ent.origin, sizeof(ent.origin));
        }

        // viewOffset 不在此区域 (它位于 pawn+0xC50, 与 origin 间隔 ~0xBD4 字节)
        // 由于 ESP 渲染使用硬编码高度 (+72) 做头部投影, 不依赖 viewOffset, 此处跳过
        ent.headPos = {ent.origin.x, ent.origin.y, ent.origin.z + 72.0f};

        // v3.29: Dormant 标志在 CGameSceneNode 内 (偏移 0xE7), 不是 pawn 实体自身
        //         之前错误地从 pawn + 0xE7 读取, 实际上读到了 pawn 的无关字段
        if (gameSceneNode) {
            ent.isDormant = Read<uint8_t>(gameSceneNode + m_offsets.m_bDormant) != 0;
        }
        ent.isScoped   = Read<uint8_t>(pawn + m_offsets.m_bIsScoped) != 0;

        // v3.28: Dormant 检查前置到屏幕投影之前, 避免浪费投影计算
        if (ent.isDormant) continue;

        ent.armor      = Read<int>(pawn + m_offsets.m_ArmorValue);
        ent.hasDefuser = Read<uint8_t>(pawn + m_offsets.m_bHasDefuser) != 0;
        ent.hasHelmet  = Read<uint8_t>(pawn + m_offsets.m_bHasHelmet) != 0;
        ent.isAlive    = true;

        // 武器 (偏移 0x1388 距离核心区太远, 单独读取)
        uintptr_t weaponHandle = Read<uint32_t>(pawn + m_offsets.m_pClippingWeapon);
        if (weaponHandle && weaponHandle != 0xFFFFFFFF) {
            uintptr_t wepListEntry = Read<uintptr_t>(elBase + 8 * ((weaponHandle & 0x7FFF) >> 9) + 16);
            wepListEntry &= ~0xFULL;  // v3.28: strip tag bits (与 pawn 解析一致)
            if (wepListEntry) {
                ent.weaponAddress = Read<uintptr_t>(wepListEntry + 120 * (weaponHandle & 0x1FF));
                if (ent.weaponAddress) {
                    uintptr_t attr = Read<uintptr_t>(ent.weaponAddress + m_offsets.m_AttributeManager);
                    uintptr_t item = Read<uintptr_t>(attr + m_offsets.m_Item);
                    ent.weaponId = Read<short>(item + m_offsets.m_ItemDefIndex);
                }
            }
        }

        // 名称 (Bot 直接从 pawn 读 m_iszPlayerName, 人类从 controller 读)
        if (isDirectPawn) {
            ent.name = ReadString(pawn + m_offsets.m_iszPlayerName, 64);
        } else {
            ent.name = ReadString(entityPtr + m_offsets.m_sSanitizedPlayerName, 64);
        }

        // 距离
        if (localPawn) {
            uintptr_t localSceneNode = Read<uintptr_t>(localPawn + m_offsets.m_pGameSceneNode);
            Vector3 localOrigin = {0, 0, 0};
            if (localSceneNode)
                localOrigin = Read<Vector3>(localSceneNode + m_offsets.m_vecOrigin);
            ent.distance = ent.origin.Distance(localOrigin) * 0.0254f;
        }

        // 屏幕投影 (v3.28: 检查返回值, 丢弃镜头后方/屏幕外的实体)
        Vector3 headWorld = {ent.origin.x, ent.origin.y, ent.origin.z + 72.0f};
        Vector3 feetWorld = {ent.origin.x, ent.origin.y, ent.origin.z};

        if (!WorldToScreen(headWorld, ent.screenHead) ||
            !WorldToScreen(feetWorld, ent.screenFeet)) {
            continue; // 镜头后方或完全在屏幕外
        }

        ent.boxHeight = ent.screenFeet.y - ent.screenHead.y;
        if (ent.boxHeight < 5.0f) ent.boxHeight = 5.0f;
        ent.boxWidth  = ent.boxHeight * 0.4f;
        if (ent.boxWidth  < 2.0f) ent.boxWidth  = 2.0f;

        // v3.29: 移除冗余 WorldToScreen(ent.origin, ent.screenPos)
        //       feetWorld==origin, ent.screenFeet 已包含脚部屏幕坐标
        //       ent.screenPos 在 ESP 渲染中从未被引用 — 纯死数据
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
    // m_vecOrigin 位于 CGameSceneNode, 需先解引用
    {
        uintptr_t localGameScene = Read<uintptr_t>(pawn + m_offsets.m_pGameSceneNode);
        if (localGameScene)
            local.origin = Read<Vector3>(localGameScene + m_offsets.m_vecOrigin);
    }
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
