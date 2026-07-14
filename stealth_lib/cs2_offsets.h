#pragma once
// ============================================================
// cs2_offsets.h — CS2 游戏偏移量配置
// 来自原始技术产品.exe 的等价实现
// 偏移值随CS2更新变化, 运行时从 config 注入
// ============================================================

#include <cstdint>
#include <cmath>

namespace cs2 {

// ============================================================
// CS2 当前版本偏移 (2026.07)
// 运行 cs2-dumper 或更新此结构后同步
// ============================================================
struct Offsets {
    // 引擎层 — 来自 a2x/cs2-dumper 2026-07-10
    uintptr_t dwViewMatrix       = 0x23A9340;
    uintptr_t dwViewAngles       = 0x23B9C78;
    uintptr_t dwLocalPlayerController = 0x237EBA0;  // controller
    uintptr_t dwLocalPlayerPawn  = 0x23A4238;        // pawn 直接指针
    uintptr_t dwEntityList       = 0x254EE60;
    uintptr_t dwGameRules        = 0x23A39D8;

    // 实体属性 (C_BaseEntity)
    uintptr_t m_iTeamNum         = 0x3BF;
    uintptr_t m_iHealth          = 0x32C;
    uintptr_t m_lifeState        = 0x338;
    uintptr_t m_vecViewOffset    = 0xC50;

    // CCSPlayerPawn
    uintptr_t m_pClippingWeapon  = 0x1388;
    uintptr_t m_hController      = 0x135C;
    uintptr_t m_iszPlayerName    = 0x640;
    uintptr_t m_aimPunchAngle    = 0x1734;
    uintptr_t m_iShotsFired      = 0x1410;
    uintptr_t m_ArmorValue       = 0x15C0;
    uintptr_t m_bHasDefuser      = 0x15C8;
    uintptr_t m_bHasHelmet       = 0x15C2;

    // CCSPlayerController
    uintptr_t m_hPlayerPawn      = 0x7EC;
    uintptr_t m_sSanitizedPlayerName = 0x760;
    uintptr_t m_bPawnIsAlive     = 0x818;

    // CGameSceneNode
    uintptr_t m_pGameSceneNode   = 0x310;
    uintptr_t m_vecOrigin        = 0x1224;        // m_vOldOrigin (CGameSceneNode)
    uintptr_t m_vecAbsOrigin     = 0x80;          // CGameSceneNode
    uintptr_t m_bDormant         = 0xE7;          // CGameSceneNode

    // CCSWeaponBaseVData
    uintptr_t m_ItemDefIndex     = 0x196;
    uintptr_t m_nModelIndex      = 0x180;

    // C_CSWeaponBase
    uintptr_t m_AttributeManager = 0x1180;
    uintptr_t m_Item             = 0x1108;

    // Bone
    uintptr_t m_modelState       = 0x160;
    uintptr_t m_hModel           = 0x140;

    // CGlowProperty
    uintptr_t m_Glow             = 0x12E8;
    uintptr_t m_iGlowType        = 0x30;
    uintptr_t m_bGlowing         = 0x31;

    // 游戏状态
    uintptr_t m_bIsScoped        = 0x13E8;
    uintptr_t m_bIsDefusing      = 0x14F9;
    uintptr_t m_iScore           = 0x504;
    uintptr_t m_iTeamScore       = 0x57C;
    uintptr_t m_iCompetitiveWins = 0x48;
};

// ============================================================
// 批量读取基准偏移 (减少 syscall 次数)
// PawnCoreBase = m_pGameSceneNode 地址
// 从此处读 256 字节覆盖 health/team/lifeState 等字段
// ============================================================
constexpr uintptr_t offsetof_PawnCore = 0x310;   // m_pGameSceneNode

// ============================================================
// 游戏内结构体
// ============================================================

#pragma pack(push, 1)

struct Vector3 {
    float x, y, z;
    Vector3 operator-(const Vector3& o) const { return {x-o.x, y-o.y, z-o.z}; }
    Vector3 operator+(const Vector3& o) const { return {x+o.x, y+o.y, z+o.z}; }
    Vector3 operator*(float s)     const { return {x*s, y*s, z*s}; }
    float Dot(const Vector3& o)    const { return x*o.x + y*o.y + z*o.z; }
    float Length()                 const { return sqrtf(x*x + y*y + z*z); }
    float Distance(const Vector3& o) const { return (*this - o).Length(); }
    Vector3 Normalized() const {
        float len = Length();
        return len > 0.001f ? Vector3{x/len, y/len, z/len} : Vector3{0,0,0};
    }
};

struct Vector2 {
    float x, y;
};

struct ViewMatrix {
    float m[4][4];
};

// 骨骼位置 (简化)
struct BoneJoint {
    Vector3 pos;
    bool    valid;
};

#pragma pack(pop)

// ============================================================
// 常用骨骼索引
// ============================================================
enum class BoneIndex : int {
    Head     = 6,   // 头部
    Neck     = 5,   // 颈部
    Chest    = 4,   // 胸部 (上胸)
    Stomach  = 3,   // 腹部 (下胸)
    Pelvis   = 0,   // 骨盆
    LShoulder = 13, // 左肩
    RShoulder = 22, // 右肩
    LElbow   = 14,  // 左肘
    RElbow   = 23,  // 右肘
    Count    = 28
};

} // namespace cs2
