// ============================================================
// cheat_overlay.cpp — 外部 Overlay 窗口实现
// 透明 + 点击穿透 + 始终置顶 + 双缓冲 GDI 渲染
// ============================================================

#include "cheat_overlay.h"
#include <cstdlib>

#ifndef WS_EX_NOREDIRECTIONBITMAP
#define WS_EX_NOREDIRECTIONBITMAP 0x00200000L
#endif

namespace cs2 {

// 窗口过程声明
LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

// 生成随机窗口类名 (EAC 检测规避: 避免静态字符串特征)
std::wstring CheatOverlay::GenerateRandomClassName() {
    static const wchar_t* prefixes[] = {
        L"DxgiOutput", L"D3DDevice", L"GpuAdapter",
        L"WmiProvider", L"ComSurrogate", L"ShellHook",
        L"CoreMessaging", L"VulkanLayer", L"OpenGLDriver"
    };
    static const wchar_t* suffixes[] = {
        L"Class", L"Ctx", L"Wnd", L"Instance", L"Proxy", L"Stub"
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    auto& prefix = prefixes[gen() % 9];
    auto& suffix = suffixes[gen() % 6];
    int num = gen() % 9000 + 1000; // 1000-9999

    wchar_t buf[64];
    swprintf_s(buf, L"%s_%s_%d", prefix, suffix, num);
    return std::wstring(buf);
}

CheatOverlay& CheatOverlay::Instance() {
    static CheatOverlay inst;
    return inst;
}

bool CheatOverlay::Create(const OverlayConfig& cfg) {
    m_config = cfg;

    // 获取桌面尺寸
    m_width  = cfg.width  ? cfg.width  : GetSystemMetrics(SM_CXSCREEN);
    m_height = cfg.height ? cfg.height : GetSystemMetrics(SM_CYSCREEN);

    // 生成随机类名 (EAC 扫描规避)
    m_className = GenerateRandomClassName();

    // 注册窗口类
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = OverlayWndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    wc.lpszClassName = m_className.c_str();

    RegisterClassExW(&wc);

    // 随机窗口标题 (EAC 扫描规避)
    wchar_t randomTitle[32];
    swprintf_s(randomTitle, L"DxOutput_%04X", GetTickCount() & 0xFFFF);

    // 创建窗口 (不使用 WS_EX_TOPMOST — 通过 SetWindowPos 每帧动态置顶)
    // EAC 检测窗口扩展风格: 移除 TOPMOST 静态标志减少特征
    m_hwnd = CreateWindowExW(
        WS_EX_TRANSPARENT |         // 点击穿透
        WS_EX_LAYERED |             // 分层窗口 (透明度)
        WS_EX_TOOLWINDOW |          // 不显示在任务栏
        WS_EX_NOREDIRECTIONBITMAP,  // 禁止DWM重定向 (降低检测面)
        m_className.c_str(),
        randomTitle,
        WS_POPUP,                   // 无边框弹出窗口
        m_config.screenX, m_config.screenY,
        m_width, m_height,
        nullptr, nullptr, wc.hInstance, nullptr
    );

    if (!m_hwnd) return false;

    // 设置透明颜色键 (使背景完全透明)
    SetLayeredWindowAttributes(m_hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);

    // 设置窗口不透明度 (仅影响非色键像素)
    SetLayeredWindowAttributes(m_hwnd, 0, 255, LWA_ALPHA);

    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);

    // 双缓冲: 创建后台缓冲区和 DC
    HDC screenDC = GetDC(nullptr);
    m_backDC     = CreateCompatibleDC(screenDC);
    m_backBmp    = CreateCompatibleBitmap(screenDC, m_width, m_height);
    SelectObject(m_backDC, m_backBmp);
    ReleaseDC(nullptr, screenDC);

    m_running = true;

    // 生成随机抖动种子 (避免 EAC 检测到确定性周期模式)
    m_jitterSeed = GetTickCount() % 0xFFFF;
    srand(m_jitterSeed);

    return true;
}

void CheatOverlay::Destroy() {
    m_running = false;
    if (m_hFont)   { DeleteObject(m_hFont);   m_hFont   = nullptr; }
    if (m_backBmp) { DeleteObject(m_backBmp); m_backBmp = nullptr; }
    if (m_backDC)  { DeleteDC(m_backDC);      m_backDC  = nullptr; }
    if (m_hwnd)    { DestroyWindow(m_hwnd);   m_hwnd    = nullptr; }
}

HDC CheatOverlay::BeginDraw() {
    if (!m_backDC) return nullptr;

    // 清空背景为黑色 (色键 → 透明)
    HBRUSH blackBrush = CreateSolidBrush(RGB(0, 0, 0));
    RECT rect = {0, 0, m_width, m_height};
    FillRect(m_backDC, &rect, blackBrush);
    DeleteObject(blackBrush);

    // 设置默认字体 (仅在必要时创建, 防止每帧泄漏 GDI 句柄)
    if (!m_hFont) {
        m_hFont = CreateFontW(
            m_config.fontSize, 0, 0, 0, FW_BOLD,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            ANTIALIASED_QUALITY, DEFAULT_PITCH,
            m_config.fontName
        );
    }
    SelectObject(m_backDC, m_hFont);

    return m_backDC;
}

void CheatOverlay::EndDraw() {
    if (!m_hwnd || !m_backDC) return;

    HDC screenDC = GetDC(m_hwnd);
    BitBlt(screenDC, 0, 0, m_width, m_height, m_backDC, 0, 0, SRCCOPY);
    ReleaseDC(m_hwnd, screenDC);
}

void CheatOverlay::BringToTop() {
    if (m_hwnd) {
        SetWindowPos(m_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

LONG CheatOverlay::GetCloakedExStyle() const {
    // 伪装模式: 移除 LAYERED → GetLayeredWindowAttributes 返回失败
    return WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOREDIRECTIONBITMAP;
}

LONG CheatOverlay::GetRenderExStyle() const {
    // 渲染模式: 完整标志 (通过 SetWindowPos 动态置顶)
    return WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOREDIRECTIONBITMAP;
}

void CheatOverlay::CloakStyle() {
    if (!m_hwnd || m_cloaked) return;
    SetWindowLongPtrW(m_hwnd, GWL_EXSTYLE, GetCloakedExStyle());
    m_cloaked = true;
}

void CheatOverlay::RestoreStyle() {
    if (!m_hwnd || !m_cloaked) return;
    SetWindowLongPtrW(m_hwnd, GWL_EXSTYLE, GetRenderExStyle());
    // 随机位置抖动 (非确定性周期, 避免EAC行为图谱匹配)
    m_frameIndex++;
    if (m_frameIndex % (5 + (rand() % 5)) == 0) { // 每5-9帧随机触发
        int offsetX = (rand() % 3) - 1;            // 随机 ±1px
        int offsetY = (rand() % 3) - 1;
        SetWindowPos(m_hwnd, HWND_TOPMOST,
                     m_config.screenX + offsetX, m_config.screenY + offsetY,
                     m_width, m_height,
                     SWP_NOACTIVATE | SWP_NOOWNERZORDER);
    } else {
        SetWindowPos(m_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    m_cloaked = false;
}

void CheatOverlay::PumpMessages() {
    MSG msg;
    while (PeekMessageW(&msg, m_hwnd, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_ERASEBKGND:
            return 1; // 不擦除背景

        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

} // namespace cs2
