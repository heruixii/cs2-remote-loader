#pragma once
// ============================================================
// cheat_overlay.h — 外部 Overlay 窗口 (透明/穿透/置顶)
// 原始产品.exe 使用 Win32 GDI 绘制ESP
// ============================================================

#include <Windows.h>
#include <string>
#include <random>

namespace cs2 {

// ============================================================
// Overlay 配置
// ============================================================
struct OverlayConfig {
    int       width         = 0;    // 0 = 全屏
    int       height        = 0;    // 0 = 全屏
    int       screenX       = 0;
    int       screenY       = 0;
    COLORREF  espBoxColor   = RGB(0, 255, 0);     // 默认绿色
    COLORREF  espTeamColor  = RGB(0, 100, 255);   // 队友蓝色
    COLORREF  espEnemyColor = RGB(255, 0, 0);     // 敌人红色
    COLORREF  textColor     = RGB(255, 255, 255);  // 白色
    int       fontSize      = 14;
    wchar_t   fontName[32]  = L"Consolas";
};

// ============================================================
// Overlay 窗口管理器
// ============================================================
class CheatOverlay {
public:
    static CheatOverlay& Instance();

    bool Create(const OverlayConfig& cfg = OverlayConfig{});
    void Destroy();

    // 获取 HDC 用于绘制 (双缓冲)
    HDC BeginDraw();
    void EndDraw();

    // 确保窗口在游戏之上 (动态 TOPMOST, 无静态标志)
    void BringToTop();

    // === EAC 规避: 窗口风格伪装 ===
    // 临时剥离 LAYERED 标志以规避 GetLayeredWindowAttributes 检测
    void CloakStyle();
    // 恢复完整渲染标志
    void RestoreStyle();

    HWND GetHwnd()     const { return m_hwnd; }
    HDC  GetBackDC()   const { return m_backDC; }
    int  Width()       const { return m_width; }
    int  Height()      const { return m_height; }
    bool IsRunning()   const { return m_running; }

    // 消息循环 (非阻塞, 在渲染循环中调用)
    void PumpMessages();
    void SetRunning(bool running) { m_running = running; }

    const OverlayConfig& GetConfig() const { return m_config; }

private:
    CheatOverlay() = default;

    // 生成随机窗口类名 (EAC 检测规避)
    static std::wstring GenerateRandomClassName();

    // EAC 规避辅助
    LONG GetCloakedExStyle() const;
    LONG GetRenderExStyle()  const;

    HWND          m_hwnd        = nullptr;
    HDC           m_backDC      = nullptr;
    HBITMAP       m_backBmp     = nullptr;
    HFONT         m_hFont       = nullptr;
    int           m_width       = 0;
    int           m_height      = 0;
    bool          m_running     = false;
    bool          m_cloaked     = false;
    int           m_frameIndex  = 0;
    int           m_jitterSeed = 0;  // 随机抖动种子, 初始化时生成
    OverlayConfig m_config;
    std::wstring  m_className;
};

} // namespace cs2
