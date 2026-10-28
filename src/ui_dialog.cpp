#include "ui_dialog.h"

#include <dwmapi.h>
#include <objidl.h>
#include <gdiplus.h>

namespace ui {
namespace {

using namespace Gdiplus;
constexpr wchar_t dialog_class[] = L"MSKAuthenticatorUpdateConfirmation";
constexpr DWORD dialog_style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
constexpr DWORD dialog_ex_style = WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT;

struct Confirmation {
    HWND owner = nullptr;
    HICON icon = nullptr;
    std::wstring version;
    float dpi = 1;
    bool accepted = false;
};

Color rgb(BYTE r, BYTE g, BYTE b) { return Color(255, r, g, b); }

void text(Graphics& graphics, const std::wstring& value, RectF bounds, float size,
          Color color, bool bold = false, bool centered = false) {
    FontFamily family(L"Segoe UI");
    Font font(&family, size, bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color);
    StringFormat format;
    format.SetLineAlignment(StringAlignmentCenter);
    format.SetAlignment(centered ? StringAlignmentCenter : StringAlignmentNear);
    format.SetFormatFlags(StringFormatFlagsNoWrap);
    graphics.DrawString(value.c_str(), -1, &font, bounds, &format, &brush);
}

void paint(HWND window, const Confirmation& state, HDC dc) {
    RECT client{};
    GetClientRect(window, &client);
    Bitmap canvas(client.right, client.bottom, PixelFormat32bppPARGB);
    Graphics graphics(&canvas);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    graphics.Clear(rgb(11, 19, 32));
    const float d = state.dpi;
    if (state.icon) {
        Bitmap icon(state.icon);
        graphics.DrawImage(&icon, RectF(28 * d, 15 * d, 28 * d, 28 * d));
    }
    text(graphics, L"MSK  AUTENTICADOR", RectF(66 * d, 14 * d, 300 * d, 30 * d),
         13 * d, rgb(224, 239, 242), true);
    Pen rule(rgb(37, 54, 71));
    graphics.DrawLine(&rule, 28 * d, 56 * d, 452 * d, 56 * d);
    text(graphics, L"Atualização disponível", RectF(28 * d, 78 * d, 424 * d, 36 * d),
         20 * d, rgb(242, 250, 249), true);
    text(graphics, L"Versão " + state.version, RectF(28 * d, 120 * d, 424 * d, 24 * d),
         12 * d, rgb(137, 229, 189), true);
    text(graphics, L"O módulo será fechado durante a instalação.",
         RectF(28 * d, 162 * d, 424 * d, 24 * d), 11 * d, rgb(159, 191, 199));
    text(graphics, L"Suas contas e chaves serão preservadas.",
         RectF(28 * d, 189 * d, 424 * d, 24 * d), 11 * d, rgb(159, 191, 199));
    Graphics screen(dc);
    screen.DrawImage(&canvas, 0, 0, client.right, client.bottom);
}

void paint_button(const DRAWITEMSTRUCT& item, float dpi) {
    Graphics graphics(item.hDC);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    graphics.Clear(rgb(11, 19, 32));
    const bool primary = item.CtlID == IDOK;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const Color fill = primary ? (pressed ? rgb(76, 196, 153) : rgb(98, 223, 178))
                               : (pressed ? rgb(33, 51, 70) : rgb(24, 39, 56));
    const Color border = (item.itemState & ODS_FOCUS) ? rgb(145, 242, 204)
                         : primary ? rgb(98, 223, 178) : rgb(58, 79, 100);
    const float width = static_cast<float>(item.rcItem.right - item.rcItem.left);
    const float height = static_cast<float>(item.rcItem.bottom - item.rcItem.top);
    const float diameter = 18 * dpi;
    GraphicsPath path;
    path.AddArc(1.0f, 1.0f, diameter, diameter, 180, 90);
    path.AddArc(width - diameter - 1, 1.0f, diameter, diameter, 270, 90);
    path.AddArc(width - diameter - 1, height - diameter - 1, diameter, diameter, 0, 90);
    path.AddArc(1.0f, height - diameter - 1, diameter, diameter, 90, 90);
    path.CloseFigure();
    SolidBrush brush(fill);
    Pen pen(border, dpi);
    graphics.FillPath(&brush, &path);
    graphics.DrawPath(&pen, &path);
    text(graphics, primary ? L"Atualizar agora" : L"Agora não", RectF(0, 0, width, height),
         11 * dpi, primary ? rgb(10, 39, 32) : rgb(225, 238, 247), true, true);
}

void layout(HWND window, Confirmation& state, UINT dpi) {
    state.dpi = static_cast<float>(dpi) / 96;
    const auto px = [dpi](int value) { return MulDiv(value, static_cast<int>(dpi), 96); };
    SetWindowPos(GetDlgItem(window, IDOK), nullptr, px(28), px(238), px(165), px(42),
                 SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(GetDlgItem(window, IDCANCEL), nullptr, px(203), px(238), px(124), px(42),
                 SWP_NOZORDER | SWP_NOACTIVATE);
    RECT frame{0, 0, px(480), px(310)};
    AdjustWindowRectExForDpi(&frame, dialog_style, FALSE, dialog_ex_style, dpi);
    RECT owner{};
    if (state.owner) GetWindowRect(state.owner, &owner);
    else {
        MONITORINFO monitor{sizeof(MONITORINFO)};
        GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST), &monitor);
        owner = monitor.rcWork;
    }
    const int width = frame.right - frame.left;
    const int height = frame.bottom - frame.top;
    SetWindowPos(window, nullptr, owner.left + (owner.right - owner.left - width) / 2,
                 owner.top + (owner.bottom - owner.top - height) / 2, width, height,
                 SWP_NOZORDER | SWP_NOACTIVATE);
    InvalidateRect(window, nullptr, FALSE);
}

LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<Confirmation*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_CREATE: {
        auto* creation = reinterpret_cast<CREATESTRUCTW*>(lparam);
        state = static_cast<Confirmation*>(creation->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        state->icon = LoadIconW(creation->hInstance, MAKEINTRESOURCEW(101));
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(state->icon));
        for (int id : {IDOK, IDCANCEL})
            CreateWindowExW(0, L"BUTTON", id == IDOK ? L"Atualizar agora" : L"Agora não",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 0, 0, window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), creation->hInstance, nullptr);
        return 0;
    }
    case WM_COMMAND:
        if (state && (LOWORD(wparam) == IDOK || LOWORD(wparam) == IDCANCEL)) {
            state->accepted = LOWORD(wparam) == IDOK;
            DestroyWindow(window);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT info{};
        HDC dc = BeginPaint(window, &info);
        if (state) paint(window, *state, dc);
        EndPaint(window, &info);
        return 0;
    }
    case WM_DRAWITEM:
        if (state) {
            paint_button(*reinterpret_cast<DRAWITEMSTRUCT*>(lparam), state->dpi);
            return TRUE;
        }
        break;
    case WM_DPICHANGED:
        if (state) layout(window, *state, HIWORD(wparam));
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

bool confirm_update(HWND owner, const std::wstring& version) {
    WNDCLASSW klass{};
    klass.hInstance = GetModuleHandleW(nullptr);
    klass.lpfnWndProc = procedure;
    klass.lpszClassName = dialog_class;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&klass);
    Confirmation state;
    state.owner = owner;
    state.version = version;
    HWND window = CreateWindowExW(dialog_ex_style, dialog_class, L"Atualizar MSK Autenticador",
        dialog_style, CW_USEDEFAULT, CW_USEDEFAULT, 480, 310, owner, nullptr, klass.hInstance, &state);
    if (!window) return false;
    BOOL dark = TRUE;
    DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    const bool owner_enabled = owner && IsWindowEnabled(owner);
    if (owner_enabled) EnableWindow(owner, FALSE);
    ShowWindow(window, SW_SHOW);
    layout(window, state, GetDpiForWindow(owner ? owner : window));
    UpdateWindow(window);
    SetFocus(GetDlgItem(window, IDCANCEL));
    MSG message{};
    bool quit = false;
    while (IsWindow(window)) {
        const BOOL result = GetMessageW(&message, nullptr, 0, 0);
        if (result <= 0) { quit = result == 0; break; }
        if (message.message == WM_KEYDOWN && message.wParam == VK_ESCAPE) {
            SendMessageW(window, WM_COMMAND, IDCANCEL, 0);
            continue;
        }
        if (message.message == WM_KEYDOWN && message.wParam == VK_RETURN) {
            SendMessageW(window, WM_COMMAND,
                GetFocus() == GetDlgItem(window, IDOK) ? IDOK : IDCANCEL, 0);
            continue;
        }
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (IsWindow(window)) DestroyWindow(window);
    if (owner_enabled) {
        EnableWindow(owner, TRUE);
        SetForegroundWindow(owner);
    }
    if (quit) PostQuitMessage(static_cast<int>(message.wParam));
    return state.accepted;
}

} // namespace ui
