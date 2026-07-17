#pragma once
// ============================================================
// game_esp.h — ESP 渲染配置与接口
// ============================================================

#include "cs2_memory.h"

namespace cs2 {

struct ESPConfig {
    bool drawBox       = true;   // 方框
    bool drawHealth    = true;   // 血条
    bool drawName      = true;   // 玩家名
    bool drawDistance  = true;   // 距离
    bool drawWeapon    = true;   // 武器名
    bool drawSnaplines = false;  // 连接线
    bool drawHeadDot   = true;   // 头部圆点
    bool drawInfo      = false;  // 额外信息
    bool drawCrosshair = true;   // 十字准星
};

class ESP {
public:
    static ESP& Instance();

    void SetConfig(const ESPConfig& cfg) { m_config = cfg; }
    const ESPConfig& GetConfig() const { return m_config; }

    // 主渲染入口
    void Render(const Entity& local, const Entity* players, int playerCount);

private:
    ESP() = default;

    void DrawBox(HDC dc, const Entity& ent, COLORREF color);
    void DrawHealthBar(HDC dc, const Entity& ent);
    void DrawName(HDC dc, const Entity& ent, COLORREF color);
    void DrawDistance(HDC dc, const Entity& ent, COLORREF color);
    void DrawWeapon(HDC dc, const Entity& ent, COLORREF color);
    void DrawSnapline(HDC dc, const Entity& ent, COLORREF color);
    void DrawHeadDot(HDC dc, const Entity& ent, bool isEnemy);
    void DrawInfo(HDC dc, const Entity& ent, const Entity& local, bool isEnemy);
    void DrawCrosshair(HDC dc, int cx, int cy);

    ESPConfig m_config;
};

} // namespace cs2
