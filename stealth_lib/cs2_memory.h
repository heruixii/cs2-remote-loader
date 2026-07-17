#pragma once
// ============================================================
// cs2_memory.h — CS2 游戏内存读写
// 基于原始技术产品.exe 的内存操作模式
// 封装: 实体遍历 / 模块基址 / 骨骼 / 视图矩阵
// ============================================================

#include "cs2_offsets.h"
#include "stealth_core.h"
#include <cstring>

namespace cs2 {

// ============================================================
// 实体信息
// ============================================================
struct Entity {
    uintptr_t address;           // 实体地址
    int       index;             // 实体索引
    uint32_t  pawnHandle;        // Pawn句柄 (m_hPlayerPawn)

    // 生命状态
    int       health;
    int       lifeState;
    int       armor;
    int       team;
    bool      isAlive;
    bool      isDormant;
    bool      isSpotted;
    bool      isScoped;
    bool      hasDefuser;
    bool      hasHelmet;

    // 位置
    Vector3   origin;            // 世界坐标
    Vector3   headPos;           // 头部位置
    Vector3   viewOffset;        // 视角偏移
    Vector2   screenPos;         // 屏幕坐标 (W2S 后)
    Vector2   screenHead;        // 头部屏幕坐标
    Vector2   screenFeet;        // 脚部屏幕坐标

    // 名称
    char name[64];

    // 武器
    uintptr_t weaponAddress;
    int       weaponId;
    char weaponName[32];

    // 距离
    float     distance;

    float     boxHeight;
    float     boxWidth;
};

// ============================================================
// CS2 内存管理器
// ============================================================
class Memory {
public:
    static Memory& Instance();

    bool Initialize(const Offsets& offsets = Offsets{});

    // 模块基址
    uintptr_t ClientBase();
    uintptr_t EngineBase();

    // 全局变量
    uintptr_t EntityList();
    uintptr_t LocalPlayerController();
    uintptr_t LocalPlayerPawn();
    ViewMatrix GetViewMatrix();

    // 实体迭代
    int GetAllPlayers(Entity* outBuf, int maxEntities, bool onlyAlive = true);

    // 局部玩家
    Entity GetLocalPlayer();

    // 骨骼位置 (简化, 使用 viewOffset 估算)
    Vector3 GetBonePosition(uintptr_t pawn, BoneIndex bone);

    // 工具
    bool WorldToScreen(const Vector3& world, Vector2& screen);
    template<typename T> T Read(uintptr_t addr);
    template<typename T> bool Write(uintptr_t addr, T value);
    void ReadString(uintptr_t addr, char* outBuf, size_t maxLen);

    // 配置
    const Offsets& GetOffsets() const { return m_offsets; }
    void SetScreenSize(int w, int h) { m_screenWidth = w; m_screenHeight = h; }

private:
    Memory() = default;

    HANDLE              m_hProcess    = nullptr;
    DWORD               m_pid         = 0;
    uintptr_t           m_clientBase  = 0;
    uintptr_t           m_engineBase  = 0;
    Offsets             m_offsets;

    // 缓存
    ViewMatrix          m_viewMatrix;
    DWORD               m_lastMatrixUpdate = 0;
    int                 m_screenWidth  = 0;
    int                 m_screenHeight = 0;

    bool ResolveModules();
};

// ============================================================
// 内联实现
// ============================================================
template<typename T>
T Memory::Read(uintptr_t addr) {
    return stealth::StealthEngine::Instance().ReadMemory<T>(addr);
}

template<typename T>
bool Memory::Write(uintptr_t addr, T value) {
    return stealth::StealthEngine::Instance().WriteMemory<T>(addr, value);
}

} // namespace cs2