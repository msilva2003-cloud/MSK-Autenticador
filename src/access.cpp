#include "access.h"

#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <dwmapi.h>
#include <objbase.h>
#include <objidl.h>
#include <gdiplus.h>
#include <shlobj.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace access {
namespace {

constexpr wchar_t dialog_class[] = L"MSKAuthenticatorPasswordDialog";
constexpr char file_magic[] = "MSKPW01";
constexpr ULONG iterations = 600000;
constexpr int password_id = 101;
constexpr int confirmation_id = 102;
constexpr UINT_PTR dpi_timer = 2;

struct Credential {
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 32> verifier{};
};

struct DialogState {
    HWND password = nullptr;
    HWND confirmation = nullptr;
    HBRUSH edit_brush = nullptr;
    HFONT edit_font = nullptr;
    HICON icon = nullptr;
    float dpi = 1.0f;
    std::wstring error;
    bool setup = false;
    bool accepted = false;
};

std::wstring credential_path() {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw)))
        throw std::runtime_error("LocalAppData indisponivel");
    std::wstring path(raw);
    CoTaskMemFree(raw);
    path += L"\\MSKAuthenticator";
    if (!CreateDirectoryW(path.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        throw std::runtime_error("Pasta local indisponivel");
    return path + L"\\access.dpapi";
}

bool derive(const std::wstring& password, const std::array<std::uint8_t, 16>& salt,
            std::array<std::uint8_t, 32>& output) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        return false;
    const auto status = BCryptDeriveKeyPBKDF2(algorithm,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(password.data())),
        static_cast<ULONG>(password.size() * sizeof(wchar_t)),
        const_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()), iterations,
        output.data(), static_cast<ULONG>(output.size()), 0);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0;
}

bool load(Credential& credential) {
    const auto path = credential_path();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return false;
        throw std::runtime_error("Nao foi possivel abrir a credencial");
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 4096) {
        CloseHandle(file);
        throw std::runtime_error("Credencial invalida");
    }
    std::vector<std::uint8_t> encrypted(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL okay = ReadFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &read, nullptr);
    CloseHandle(file);
    if (!okay || read != encrypted.size()) throw std::runtime_error("Leitura da credencial incompleta");
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), encrypted.data()}, plain{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain))
        throw std::runtime_error("Nao foi possivel validar a credencial protegida");
    const auto expected = sizeof(file_magic) - 1 + credential.salt.size() + credential.verifier.size();
    bool valid = plain.cbData == expected &&
        std::memcmp(plain.pbData, file_magic, sizeof(file_magic) - 1) == 0;
    if (valid) {
        auto* cursor = plain.pbData + sizeof(file_magic) - 1;
        std::memcpy(credential.salt.data(), cursor, credential.salt.size());
        cursor += credential.salt.size();
        std::memcpy(credential.verifier.data(), cursor, credential.verifier.size());
    }
    SecureZeroMemory(plain.pbData, plain.cbData);
    LocalFree(plain.pbData);
    SecureZeroMemory(encrypted.data(), encrypted.size());
    if (!valid) throw std::runtime_error("Formato de credencial invalido");
    return true;
}

void save(const Credential& credential) {
    std::vector<std::uint8_t> plain;
    plain.insert(plain.end(), reinterpret_cast<const std::uint8_t*>(file_magic),
                 reinterpret_cast<const std::uint8_t*>(file_magic) + sizeof(file_magic) - 1);
    plain.insert(plain.end(), credential.salt.begin(), credential.salt.end());
    plain.insert(plain.end(), credential.verifier.begin(), credential.verifier.end());
    DATA_BLOB input{static_cast<DWORD>(plain.size()), plain.data()}, encrypted{};
    if (!CryptProtectData(&input, L"MSK Autenticador password", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) {
        SecureZeroMemory(plain.data(), plain.size());
        throw std::runtime_error("Nao foi possivel proteger a credencial");
    }
    const auto path = credential_path();
    const auto temporary = path + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(plain.data(), plain.size());
        SecureZeroMemory(encrypted.pbData, encrypted.cbData);
        LocalFree(encrypted.pbData);
        throw std::runtime_error("Nao foi possivel salvar a credencial");
    }
    DWORD written = 0;
    BOOL okay = WriteFile(file, encrypted.pbData, encrypted.cbData, &written, nullptr);
    if (okay) okay = FlushFileBuffers(file);
    CloseHandle(file);
    SecureZeroMemory(plain.data(), plain.size());
    SecureZeroMemory(encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
    if (!okay || written != encrypted.cbData ||
        !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("Nao foi possivel concluir o salvamento da credencial");
    }
}

bool verify_or_create(const std::wstring& password, const std::wstring& confirmation,
                      bool setup, std::wstring& error) {
    if (password.size() < 8) {
        error = L"Use uma senha com pelo menos 8 caracteres.";
        return false;
    }
    Credential credential;
    if (setup) {
        if (password != confirmation) {
            error = L"As senhas não coincidem.";
            return false;
        }
        if (BCryptGenRandom(nullptr, credential.salt.data(), static_cast<ULONG>(credential.salt.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !derive(password, credential.salt, credential.verifier))
            throw std::runtime_error("Nao foi possivel preparar a senha");
        save(credential);
        SecureZeroMemory(credential.verifier.data(), credential.verifier.size());
        return true;
    }
    if (!load(credential)) {
        error = L"Credencial não encontrada. Abra o módulo novamente.";
        return false;
    }
    std::array<std::uint8_t, 32> candidate{};
    const bool okay = derive(password, credential.salt, candidate);
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < candidate.size(); ++i)
        difference |= candidate[i] ^ credential.verifier[i];
    const bool matches = okay && difference == 0;
    SecureZeroMemory(candidate.data(), candidate.size());
    SecureZeroMemory(credential.verifier.data(), credential.verifier.size());
    if (!matches) error = L"Senha incorreta.";
    return matches;
}

using namespace Gdiplus;

Color rgb(BYTE red, BYTE green, BYTE blue) { return Color(255, red, green, blue); }

void rounded(Graphics& graphics, RectF bounds, float radius, const Color& fill,
             const Color& border) {
    GraphicsPath path;
    const float diameter = radius * 2;
    path.AddArc(bounds.X, bounds.Y, diameter, diameter, 180, 90);
    path.AddArc(bounds.GetRight() - diameter, bounds.Y, diameter, diameter, 270, 90);
    path.AddArc(bounds.GetRight() - diameter, bounds.GetBottom() - diameter, diameter, diameter, 0, 90);
    path.AddArc(bounds.X, bounds.GetBottom() - diameter, diameter, diameter, 90, 90);
    path.CloseFigure();
    SolidBrush brush(fill);
    Pen pen(border, 1);
    graphics.FillPath(&brush, &path);
    graphics.DrawPath(&pen, &path);
}

void draw_text(Graphics& graphics, const std::wstring& value, RectF bounds,
               float size, Color color, bool bold = false) {
    FontFamily family(L"Segoe UI");
    Font font(&family, size, bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color);
    StringFormat format;
    format.SetLineAlignment(StringAlignmentCenter);
    format.SetTrimming(StringTrimmingEllipsisCharacter);
    format.SetFormatFlags(StringFormatFlagsNoWrap);
    graphics.DrawString(value.c_str(), -1, &font, bounds, &format, &brush);
}

void paint_dialog(HWND window, const DialogState& state, HDC dc) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    Bitmap canvas(width, height, PixelFormat32bppPARGB);
    Graphics graphics(&canvas);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    graphics.Clear(rgb(11, 19, 32));
    const float d = state.dpi;
    if (state.icon) {
        Bitmap icon(state.icon);
        graphics.DrawImage(&icon, RectF(28 * d, 15 * d, 28 * d, 28 * d));
    }
    draw_text(graphics, L"MSK  AUTENTICADOR", RectF(66 * d, 14 * d, 260 * d, 30 * d),
              13 * d, rgb(224, 239, 242), true);
    Pen rule(rgb(37, 54, 71));
    graphics.DrawLine(&rule, 28 * d, 56 * d, width - 28 * d, 56 * d);
    draw_text(graphics, state.setup ? L"Crie sua senha" : L"Acesso protegido",
              RectF(28 * d, 77 * d, width - 56 * d, 38 * d),
              20 * d, rgb(242, 250, 249), true);
    draw_text(graphics, state.setup ? L"Use pelo menos 8 caracteres para abrir o módulo."
                                     : L"Digite sua senha para abrir o módulo.",
              RectF(28 * d, 119 * d, width - 56 * d, 25 * d),
              11 * d, rgb(159, 191, 199));
    draw_text(graphics, L"SENHA", RectF(28 * d, 157 * d, 180 * d, 20 * d),
              10 * d, rgb(137, 229, 189), true);
    if (state.setup)
        draw_text(graphics, L"CONFIRMAR SENHA", RectF(28 * d, 239 * d, 220 * d, 20 * d),
                  10 * d, rgb(137, 229, 189), true);
    if (!state.error.empty())
        draw_text(graphics, state.error,
                  RectF(28 * d, (state.setup ? 319.0f : 237.0f) * d,
                        width - 56 * d, 24 * d),
                  11 * d, rgb(245, 165, 168));
    Graphics screen(dc);
    screen.DrawImage(&canvas, 0, 0, width, height);
}

void draw_button(const DRAWITEMSTRUCT& item, float dpi, bool setup) {
    Graphics graphics(item.hDC);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    const int width = item.rcItem.right - item.rcItem.left;
    const int height = item.rcItem.bottom - item.rcItem.top;
    SolidBrush background(rgb(11, 19, 32));
    graphics.FillRectangle(&background, 0, 0, width, height);
    const bool primary = item.CtlID == IDOK;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const Color fill = primary ? (pressed ? rgb(76, 196, 153) : rgb(98, 223, 178))
                               : (pressed ? rgb(33, 51, 70) : rgb(24, 39, 56));
    const Color border = (item.itemState & ODS_FOCUS) ? rgb(145, 242, 204) :
                         primary ? rgb(98, 223, 178) : rgb(58, 79, 100);
    rounded(graphics, RectF(1, 1, width - 2.0f, height - 2.0f), 9 * dpi, fill, border);
    const std::wstring title = primary ? (setup ? L"Criar senha" : L"Desbloquear") : L"Sair";
    FontFamily family(L"Segoe UI");
    Font font(&family, 11 * dpi, FontStyleBold, UnitPixel);
    SolidBrush text_brush(primary ? rgb(10, 39, 32) : rgb(225, 238, 247));
    StringFormat format;
    format.SetAlignment(StringAlignmentCenter);
    format.SetLineAlignment(StringAlignmentCenter);
    graphics.DrawString(title.c_str(), -1, &font,
                        RectF(0, 0, static_cast<float>(width), static_cast<float>(height)),
                        &format, &text_brush);
}

void layout_dialog(HWND window, DialogState& state, float dpi) {
    state.dpi = dpi;
    const auto px = [dpi](int value) { return static_cast<int>(value * dpi + 0.5f); };
    const UINT flags = SWP_NOZORDER | SWP_NOACTIVATE;
    SetWindowPos(state.password, nullptr, px(28), px(183), px(424), px(40), flags);
    SendMessageW(state.password, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                 MAKELPARAM(px(10), px(10)));
    if (state.confirmation)
        SetWindowPos(state.confirmation, nullptr, px(28), px(265), px(424), px(40), flags);
    if (state.confirmation)
        SendMessageW(state.confirmation, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELPARAM(px(10), px(10)));
    SetWindowPos(GetDlgItem(window, IDOK), nullptr, px(28), px(state.setup ? 351 : 270),
                 px(165), px(42), flags);
    SetWindowPos(GetDlgItem(window, IDCANCEL), nullptr, px(203), px(state.setup ? 351 : 270),
                 px(120), px(42), flags);
    HFONT font = CreateFontW(-px(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    if (font) {
        SendMessageW(state.password, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        if (state.confirmation)
            SendMessageW(state.confirmation, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        if (state.edit_font) DeleteObject(state.edit_font);
        state.edit_font = font;
    }
    InvalidateRect(window, nullptr, FALSE);
}

void fit_dialog(HWND window, DialogState& state, float dpi) {
    layout_dialog(window, state, dpi);
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (!GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST), &monitor)) return;
    const RECT& work = monitor.rcWork;
    const int width = static_cast<int>(496 * dpi + 0.5f);
    const int height = static_cast<int>((state.setup ? 460 : 375) * dpi + 0.5f);
    const int x = work.left + ((work.right - work.left) - width) / 2;
    const int y = work.top + ((work.bottom - work.top) - height) / 2;
    SetWindowPos(window, HWND_TOPMOST, x, y, width, height, SWP_NOACTIVATE);
}

LRESULT CALLBACK dialog_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<DialogState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_CREATE) {
        auto* creation = reinterpret_cast<CREATESTRUCTW*>(lparam);
        state = static_cast<DialogState*>(creation->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        state->dpi = static_cast<float>(GetDpiForWindow(window)) / 96.0f;
        const auto px = [state](int value) { return static_cast<int>(value * state->dpi + 0.5f); };
        state->edit_brush = CreateSolidBrush(RGB(20, 34, 49));
        state->icon = LoadIconW(creation->hInstance, MAKEINTRESOURCEW(101));
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(state->icon));
        state->password = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
            px(28), px(183), px(424), px(40), window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(password_id)), creation->hInstance, nullptr);
        SendMessageW(state->password, EM_LIMITTEXT, 128, 0);
        SendMessageW(state->password, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELPARAM(px(10), px(10)));
        if (state->setup) {
            state->confirmation = CreateWindowExW(0, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                px(28), px(265), px(424), px(40), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(confirmation_id)), creation->hInstance, nullptr);
            SendMessageW(state->confirmation, EM_LIMITTEXT, 128, 0);
            SendMessageW(state->confirmation, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                         MAKELPARAM(px(10), px(10)));
        }
        const int button_y = px(state->setup ? 351 : 270);
        CreateWindowExW(0, L"BUTTON", state->setup ? L"Criar senha" : L"Desbloquear",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            px(28), button_y, px(165), px(42), window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)), creation->hInstance, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Sair", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            px(203), button_y, px(120), px(42), window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)), creation->hInstance, nullptr);
        layout_dialog(window, *state, state->dpi);
        SetFocus(state->password);
        return 0;
    }
    if (message == WM_COMMAND && state) {
        if (LOWORD(wparam) == IDCANCEL) {
            DestroyWindow(window);
            return 0;
        }
        if (LOWORD(wparam) == IDOK) {
            wchar_t password[256]{}, confirmation[256]{};
            GetWindowTextW(state->password, password, static_cast<int>(std::size(password)));
            if (state->confirmation)
                GetWindowTextW(state->confirmation, confirmation, static_cast<int>(std::size(confirmation)));
            state->error.clear();
            try {
                state->accepted = verify_or_create(password, confirmation, state->setup, state->error);
            } catch (...) {
                state->error = L"Não foi possível salvar ou validar a senha no Windows.";
            }
            SecureZeroMemory(password, sizeof(password));
            SecureZeroMemory(confirmation, sizeof(confirmation));
            if (state->accepted) {
                SetWindowTextW(state->password, L"");
                if (state->confirmation) SetWindowTextW(state->confirmation, L"");
                DestroyWindow(window);
            } else {
                InvalidateRect(window, nullptr, FALSE);
                HWND focus = state->error == L"As senhas não coincidem." ? state->confirmation : state->password;
                SetFocus(focus);
                SendMessageW(focus, EM_SETSEL, 0, -1);
            }
            return 0;
        }
    }
    if (message == WM_CTLCOLOREDIT && state) {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetTextColor(dc, RGB(234, 244, 248));
        SetBkColor(dc, RGB(20, 34, 49));
        return reinterpret_cast<LRESULT>(state->edit_brush);
    }
    if (message == WM_DRAWITEM && state) {
        auto* item = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
        if (item->CtlID == IDOK || item->CtlID == IDCANCEL) {
            draw_button(*item, state->dpi, state->setup);
            return TRUE;
        }
    }
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_PAINT && state) {
        PAINTSTRUCT info{};
        HDC dc = BeginPaint(window, &info);
        paint_dialog(window, *state, dc);
        EndPaint(window, &info);
        return 0;
    }
    if (message == WM_TIMER && state && wparam == dpi_timer) {
        const float dpi = static_cast<float>(GetDpiForWindow(window)) / 96.0f;
        if (dpi != state->dpi) fit_dialog(window, *state, dpi);
        return 0;
    }
    if (message == WM_DPICHANGED && state) {
        const float dpi = static_cast<float>(HIWORD(wparam)) / 96.0f;
        fit_dialog(window, *state, dpi);
        return 0;
    }
    if (message == WM_CLOSE && state) {
        DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY) KillTimer(window, dpi_timer);
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

bool authenticate() {
    Credential existing;
    const bool setup = !load(existing);
    SecureZeroMemory(existing.verifier.data(), existing.verifier.size());
    WNDCLASSW klass{};
    klass.hInstance = GetModuleHandleW(nullptr);
    klass.lpfnWndProc = dialog_proc;
    klass.lpszClassName = dialog_class;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&klass);
    DialogState state;
    state.setup = setup;
    HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, dialog_class,
        setup ? L"Criar senha — MSK Autenticador" : L"Desbloquear — MSK Autenticador",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 496, setup ? 460 : 375,
        nullptr, nullptr, klass.hInstance, &state);
    if (!dialog) {
        if (state.edit_brush) DeleteObject(state.edit_brush);
        if (state.edit_font) DeleteObject(state.edit_font);
        return false;
    }
    BOOL dark = TRUE;
    DwmSetWindowAttribute(dialog, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    ShowWindow(dialog, SW_SHOW);
    fit_dialog(dialog, state, static_cast<float>(GetDpiForWindow(dialog)) / 96.0f);
    SetTimer(dialog, dpi_timer, 500, nullptr);
    UpdateWindow(dialog);
    SetForegroundWindow(dialog);
    SetFocus(state.password);
    MSG message{};
    while (IsWindow(dialog) && GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (message.message == WM_KEYDOWN && message.wParam == VK_ESCAPE) {
            DestroyWindow(dialog);
            break;
        }
        if (message.message == WM_KEYDOWN && message.wParam == VK_RETURN) {
            SendMessageW(dialog, WM_COMMAND, IDOK, 0);
            continue;
        }
        if (IsDialogMessageW(dialog, &message)) continue;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    if (state.edit_brush) DeleteObject(state.edit_brush);
    if (state.edit_font) DeleteObject(state.edit_font);
    return state.accepted;
}

} // namespace access
