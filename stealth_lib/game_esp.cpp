// ============================================================
// game_esp.cpp — ESP 渲染实现
// 方框 / 血条 / 玩家名 / 距离 / 武器 / 瞄准线
// ============================================================

#include "game_esp.h"
#include "cheat_overlay.h"
#include <cmath>
#include <cstdio>

namespace cs2 {

ESP& ESP::Instance() {
    static ESP inst;
    return inst;
}

void ESP::Render(const Entity& local, const std::vector<Entity>& players) {
    auto& overlay = CheatOverlay::Instance();
    HDC dc = overlay.GetBackDC();
    if (!dc) return;

    const auto& cfg = overlay.GetConfig();

    // AA 质量
    SetBkMode(dc, TRANSPARENT);

    for (const auto& ent : players) {
        if (!ent.isAlive || ent.isDormant) continue;
        if (ent.screenFeet.y < 0 || ent.screenHead.y < 0) continue;
        if (ent.boxHeight < 5.0f) continue;

        bool isEnemy = (ent.team != local.team);
        COLORREF color = isEnemy ? cfg.espEnemyColor : cfg.espTeamColor;

        if (m_config.drawBox)    DrawBox(dc, ent, color);
        if (m_config.drawHealth) DrawHealthBar(dc, ent);
        if (m_config.drawName)   DrawName(dc, ent, color);
        if (m_config.drawDistance) DrawDistance(dc, ent, color);
        if (m_config.drawWeapon) DrawWeapon(dc, ent, color);
        if (m_config.drawSnaplines) DrawSnapline(dc, ent, color);
        if (m_config.drawHeadDot) DrawHeadDot(dc, ent, isEnemy);
        if (m_config.drawInfo)   DrawInfo(dc, ent, local, isEnemy);
    }

    // 十字准星
    if (m_config.drawCrosshair) {
        DrawCrosshair(dc, overlay.Width() / 2, overlay.Height() / 2);
    }
}

void ESP::DrawBox(HDC dc, const Entity& ent, COLORREF color) {
    float x = ent.screenHead.x - ent.boxWidth / 2;
    float y = ent.screenHead.y;
    float w = ent.boxWidth;
    float h = ent.boxHeight;

    // 外轮廓 (黑色, 2px)
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(0, 0, 0));
    HPEN oldPen = (HPEN)SelectObject(dc, pen);
    Rectangle(dc, (int)(x - 1), (int)(y - 1), (int)(x + w + 1), (int)(y + h + 1));
    SelectObject(dc, oldPen);  // 先还原再删除, 避免选中状态下 Delete
    DeleteObject(pen);

    // 内框 (主体色, 1px)
    pen = CreatePen(PS_SOLID, 1, color);
    oldPen = (HPEN)SelectObject(dc, pen);
    Rectangle(dc, (int)x, (int)y, (int)(x + w), (int)(y + h));
    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

void ESP::DrawHealthBar(HDC dc, const Entity& ent) {
    float x = ent.screenHead.x - ent.boxWidth / 2 - 6;
    float y = ent.screenHead.y;
    float h = ent.boxHeight;
    float barW = 4;

    // 背景
    HBRUSH bgBrush = CreateSolidBrush(RGB(0, 0, 0));
    RECT bgRect = {(int)x, (int)y, (int)(x + barW), (int)(y + h)};
    FillRect(dc, &bgRect, bgBrush);
    DeleteObject(bgBrush);

    // 血量: 绿色→黄色→红色
    float healthRatio = (float)ent.health / 100.0f;
    float healthH = h * healthRatio;
    int r = (int)(255 * (1.0f - healthRatio));
    int g = (int)(255 * healthRatio);
    COLORREF healthColor = RGB(r, g, 0);

    HBRUSH healthBrush = CreateSolidBrush(healthColor);
    RECT healthRect = {(int)x, (int)(y + h - healthH), (int)(x + barW), (int)(y + h)};
    FillRect(dc, &healthRect, healthBrush);
    DeleteObject(healthBrush);
}

void ESP::DrawName(HDC dc, const Entity& ent, COLORREF color) {
    if (ent.name.empty()) return;

    std::string displayName = ent.name;
    // 限制名称长度
    if (displayName.length() > 16) {
        displayName = displayName.substr(0, 15) + "...";
    }

    SetTextColor(dc, color);
    float x = ent.screenHead.x + ent.boxWidth / 2 + 4;
    float y = ent.screenHead.y - 2;

    TextOutA(dc, (int)x, (int)y, displayName.c_str(), (int)displayName.length());
}

void ESP::DrawDistance(HDC dc, const Entity& ent, COLORREF color) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.0fm", ent.distance);
    SetTextColor(dc, color);

    float x = ent.screenHead.x + ent.boxWidth / 2 + 4;
    float y = ent.screenHead.y + 14;

    TextOutA(dc, (int)x, (int)y, buf, (int)strlen(buf));
}

void ESP::DrawWeapon(HDC dc, const Entity& ent, COLORREF color) {
    const char* wpn = "??";
    // 常见武器ID映射
    switch (ent.weaponId) {
        case 1:  wpn = "DE";  break;
        case 4:  wpn = "Glock"; break;
        case 7:  wpn = "AK47"; break;
        case 8:  wpn = "AUG"; break;
        case 9:  wpn = "AWP"; break;
        case 11: wpn = "G3SG1"; break;
        case 13: wpn = "P2000"; break;
        case 16: wpn = "M4A4"; break;
        case 17: wpn = "MAC10"; break;
        case 19: wpn = "P90"; break;
        case 24: wpn = "UMP45"; break;
        case 25: wpn = "XM1014"; break;
        case 26: wpn = "Bizon"; break;
        case 27: wpn = "MAG7"; break;
        case 28: wpn = "Negev"; break;
        case 29: wpn = "SawedOff"; break;
        case 30: wpn = "Tec9"; break;
        case 32: wpn = "P250"; break;
        case 34: wpn = "MP9"; break;
        case 36: wpn = "Nova"; break;
        case 38: wpn = "SCAR20"; break;
        case 39: wpn = "SG553"; break;
        case 40: wpn = "SSG08"; break;
        case 43: wpn = "FAMAS"; break;
        case 46: wpn = "M249"; break;
        case 48: wpn = "P90"; break;
        case 60: wpn = "M4A1-S"; break;
        case 61: wpn = "USP-S"; break;
        case 63: wpn = "CZ75"; break;
        case 64: wpn = "R8"; break;
        default: break;
    }

    SetTextColor(dc, color);
    float x = ent.screenHead.x + ent.boxWidth / 2 + 4;
    float y = ent.screenHead.y + 28;
    TextOutA(dc, (int)x, (int)y, wpn, (int)strlen(wpn));
}

void ESP::DrawSnapline(HDC dc, const Entity& ent, COLORREF color) {
    int centerX = CheatOverlay::Instance().Width() / 2;
    int bottomY = CheatOverlay::Instance().Height();

    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HPEN oldPen = (HPEN)SelectObject(dc, pen);

    MoveToEx(dc, centerX, bottomY, nullptr);
    LineTo(dc, (int)ent.screenFeet.x, (int)ent.screenFeet.y);

    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

void ESP::DrawHeadDot(HDC dc, const Entity& ent, bool isEnemy) {
    if (!m_config.drawHeadDot) return;

    COLORREF color = isEnemy ? RGB(255, 255, 0) : RGB(100, 200, 255);
    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, color);

    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen   = SelectObject(dc, pen);

    int radius = (int)(ent.boxWidth * 0.3f + 1.0f);
    if (radius < 3) radius = 3;
    Ellipse(dc,
            (int)(ent.screenHead.x - radius),
            (int)(ent.screenHead.y - radius),
            (int)(ent.screenHead.x + radius),
            (int)(ent.screenHead.y + radius));

    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);
}

void ESP::DrawInfo(HDC dc, const Entity& ent, const Entity& local, bool isEnemy) {
    COLORREF color = isEnemy ? RGB(200, 200, 200) : RGB(180, 220, 255);
    SetTextColor(dc, color);

    float x = ent.screenHead.x + ent.boxWidth / 2 + 4;
    float y = ent.screenHead.y + 42;

    char healthBuf[32];
    snprintf(healthBuf, sizeof(healthBuf), "HP:%d", ent.health);
    TextOutA(dc, (int)x, (int)y, healthBuf, (int)strlen(healthBuf));

    if (ent.isScoped) {
        SetTextColor(dc, RGB(255, 100, 100));
        TextOutA(dc, (int)x, (int)(y + 14), "SCOPED", 6);
    }
}

void ESP::DrawCrosshair(HDC dc, int cx, int cy) {
    int size = 8;
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(0, 255, 0));
    HPEN oldPen = (HPEN)SelectObject(dc, pen);

    MoveToEx(dc, cx - size, cy, nullptr);
    LineTo(dc, cx + size, cy);
    MoveToEx(dc, cx, cy - size, nullptr);
    LineTo(dc, cx, cy + size);

    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

} // namespace cs2
