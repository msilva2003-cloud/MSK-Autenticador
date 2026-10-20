#include "authenticator.h"

#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <objbase.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

using namespace Gdiplus;

constexpr wchar_t window_class[] = L"MSKAuthenticatorWindow";
constexpr UINT_PTR timer_refresh = 1;
constexpr int edit_account = 1001;
constexpr int delete_account = 1002;

std::wstring account_title(const auth::Account& account);

struct State {
    HWND window = nullptr;
    HICON icon = nullptr;
    std::vector<auth::Account> accounts;
    std::wstring notice = L"Os códigos estão ocultos.";
    bool revealed = false;
    int hovered = -1;
    int focused = 0;
    float scroll = 0;
    float dpi = 1;
    std::wstring copied_code;
    std::chrono::steady_clock::time_point copied_at{};
    std::chrono::steady_clock::time_point copied_toast_until{};
    bool copied_toast_visible = false;
    int drag_candidate = -1;
    int drag_target = -1;
    POINT drag_start{};
    bool dragging = false;
    std::chrono::steady_clock::time_point last_action = std::chrono::steady_clock::now();
};

Color rgb(BYTE r, BYTE g, BYTE b) { return Color(255, r, g, b); }
float scale(const State& state, float value) { return value * state.dpi; }

void rounded(Graphics& graphics, RectF bounds, float radius, const Color& fill,
             const Color* border = nullptr, float border_width = 1) {
    GraphicsPath path;
    const float diameter = std::min(radius * 2, std::min(bounds.Width, bounds.Height));
    path.AddArc(bounds.X, bounds.Y, diameter, diameter, 180, 90);
    path.AddArc(bounds.GetRight() - diameter, bounds.Y, diameter, diameter, 270, 90);
    path.AddArc(bounds.GetRight() - diameter, bounds.GetBottom() - diameter, diameter, diameter, 0, 90);
    path.AddArc(bounds.X, bounds.GetBottom() - diameter, diameter, diameter, 90, 90);
    path.CloseFigure();
    SolidBrush brush(fill);
    graphics.FillPath(&brush, &path);
    if (border) {
        Pen pen(*border, border_width);
        graphics.DrawPath(&pen, &path);
    }
}

void label(Graphics& graphics, const State& state, const std::wstring& value,
           RectF bounds, float font_size, Color color, bool bold = false,
           StringAlignment alignment = StringAlignmentNear) {
    FontFamily family(L"Segoe UI");
    Font font(&family, scale(state, font_size), bold ? FontStyleBold : FontStyleRegular, UnitPixel);
    SolidBrush brush(color);
    StringFormat format;
    format.SetAlignment(alignment);
    format.SetLineAlignment(StringAlignmentCenter);
    format.SetTrimming(StringTrimmingEllipsisCharacter);
    format.SetFormatFlags(StringFormatFlagsNoWrap);
    graphics.DrawString(value.c_str(), -1, &font, bounds, &format, &brush);
}

void line(Graphics& graphics, Color color, float x1, float y1, float x2, float y2, float width = 1) {
    Pen pen(color, width);
    graphics.DrawLine(&pen, x1, y1, x2, y2);
}

RectF button_rect(const State& state, int id) {
    const float x = scale(state, 28), y = scale(state, 167);
    if (id == 0) return RectF(x, y, scale(state, 145), scale(state, 35));
    return RectF(x + scale(state, 155), y, scale(state, 155), scale(state, 35));
}

bool inside(RectF area, float x, float y) {
    return x >= area.X && x <= area.GetRight() && y >= area.Y && y <= area.GetBottom();
}

float content_top(const State& state) { return scale(state, 237); }
float card_height(const State& state) { return scale(state, 86); }
float card_step(const State& state) { return scale(state, 94); }

RectF card_bounds(const State& state, float width, int index) {
    return RectF(scale(state, 28), content_top(state) + index * card_step(state) - state.scroll,
                 width - scale(state, 56), card_height(state));
}

RectF code_bounds(const State& state, float width, int index) {
    auto card = card_bounds(state, width, index);
    return RectF(card.GetRight() - scale(state, 190), card.Y + scale(state, 9),
                 scale(state, 177), scale(state, 43));
}

RectF action_bounds(const State& state, float width, int index, int action) {
    auto card = card_bounds(state, width, index);
    return RectF(card.X + scale(state, action == edit_account ? 196.0f : 268.0f),
                 card.Y + scale(state, 56), scale(state, 65), scale(state, 21));
}

int account_at(const State& state, float width, float height, float x, float y) {
    if (y < content_top(state) || y >= height - scale(state, 48)) return -1;
    for (int index = 0; index < static_cast<int>(state.accounts.size()); ++index) {
        if (inside(card_bounds(state, width, index), x, y)) return index;
    }
    return -1;
}

void wipe_accounts(State& state) {
    for (auto& account : state.accounts) auth::wipe(account.secret);
}

void hide(State& state) {
    if (!state.revealed) return;
    state.revealed = false;
    state.copied_toast_visible = false;
    wipe_accounts(state);
    state.notice = L"Os códigos estão ocultos.";
    InvalidateRect(state.window, nullptr, FALSE);
}

void show(State& state) {
    auto loaded = auth::load_vault();
    wipe_accounts(state);
    state.accounts = std::move(loaded);
    state.revealed = true;
    state.last_action = std::chrono::steady_clock::now();
    state.notice = L"Códigos visíveis. Dê dois cliques em um código para copiar.";
    InvalidateRect(state.window, nullptr, FALSE);
}

void import_qr(State& state) {
    wchar_t filename[MAX_PATH]{};
    OPENFILENAMEW options{};
    options.lStructSize = sizeof(options);
    options.hwndOwner = state.window;
    options.lpstrFilter = L"Imagens de QR\0*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff\0Todos os arquivos\0*.*\0";
    options.lpstrFile = filename;
    options.nMaxFile = MAX_PATH;
    options.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&options)) return;

    auto imported = auth::read_qr_image(filename);
    SecureZeroMemory(filename, sizeof(filename));
    auto full = auth::load_vault();
    int added = 0;
    for (auto& account : imported) {
        const bool duplicate = std::any_of(full.begin(), full.end(), [&](const auth::Account& saved) {
            return saved.name == account.name && saved.issuer == account.issuer &&
                   saved.secret == account.secret;
        });
        if (!duplicate) {
            full.push_back(std::move(account));
            ++added;
        }
    }
    if (added == 0) {
        state.notice = L"Esse QR não contém contas novas.";
        InvalidateRect(state.window, nullptr, FALSE);
        return;
    }
    auth::save_vault(full);
    if (state.revealed) {
        state.accounts = std::move(full);
    } else {
        for (auto& account : full) auth::wipe(account.secret);
        state.accounts = std::move(full);
    }
    state.notice = std::to_wstring(added) + L" conta(s) importada(s). Se houver vários QRs, importe cada imagem.";
    InvalidateRect(state.window, nullptr, FALSE);
}

void act(State& state, int id) {
    state.last_action = std::chrono::steady_clock::now();
    if (id == 0) import_qr(state);
    if (id == 1) {
        if (state.revealed) hide(state);
        else show(state);
    }
}

void clear_copied_code(State& state) {
    if (state.copied_code.empty()) return;
    if (OpenClipboard(state.window)) {
        HANDLE data = GetClipboardData(CF_UNICODETEXT);
        if (data) {
            const auto* text = static_cast<const wchar_t*>(GlobalLock(data));
            if (text) {
                const bool same = state.copied_code == text;
                GlobalUnlock(data);
                if (same) EmptyClipboard();
            }
        }
        CloseClipboard();
    }
    SecureZeroMemory(state.copied_code.data(), state.copied_code.size() * sizeof(wchar_t));
    state.copied_code.clear();
}

void copy_account_code(State& state, int index) {
    if (!state.revealed || index < 0 || index >= static_cast<int>(state.accounts.size())) return;
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    auto code = auth::totp(state.accounts[index], seconds);
    if (!OpenClipboard(state.window)) {
        SecureZeroMemory(code.data(), code.size() * sizeof(wchar_t));
        state.notice = L"A área de transferência está ocupada. Tente novamente.";
        InvalidateRect(state.window, nullptr, FALSE);
        return;
    }
    const auto bytes = (code.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    bool copied = false;
    if (memory) {
        void* buffer = GlobalLock(memory);
        if (buffer) {
            std::memcpy(buffer, code.c_str(), bytes);
            GlobalUnlock(memory);
            if (EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, memory)) {
                copied = true;
                memory = nullptr;
            }
        }
        if (memory) GlobalFree(memory);
    }
    CloseClipboard();
    if (copied) {
        SecureZeroMemory(state.copied_code.data(), state.copied_code.size() * sizeof(wchar_t));
        state.copied_code = code;
        state.copied_at = std::chrono::steady_clock::now();
        state.copied_toast_until = state.copied_at + std::chrono::seconds(2);
        state.copied_toast_visible = true;
        state.last_action = state.copied_at;
    } else {
        state.notice = L"Não foi possível copiar o código.";
    }
    SecureZeroMemory(code.data(), code.size() * sizeof(wchar_t));
    InvalidateRect(state.window, nullptr, FALSE);
}

struct NamePrompt {
    std::wstring value;
    bool accepted = false;
    HWND edit = nullptr;
};

LRESULT CALLBACK name_prompt_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* prompt = reinterpret_cast<NamePrompt*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_CREATE: {
        auto* creation = reinterpret_cast<CREATESTRUCTW*>(lparam);
        prompt = static_cast<NamePrompt*>(creation->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(prompt));
        CreateWindowExW(0, L"STATIC", L"Nome exibido:", WS_CHILD | WS_VISIBLE,
                        20, 18, 330, 24, window, nullptr, creation->hInstance, nullptr);
        prompt->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", prompt->value.c_str(),
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                      20, 48, 350, 30, window, reinterpret_cast<HMENU>(101),
                                      creation->hInstance, nullptr);
        SendMessageW(prompt->edit, EM_LIMITTEXT, 120, 0);
        CreateWindowExW(0, L"BUTTON", L"Salvar", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                        188, 96, 86, 29, window, reinterpret_cast<HMENU>(IDOK), creation->hInstance, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Cancelar", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                        283, 96, 87, 29, window, reinterpret_cast<HMENU>(IDCANCEL), creation->hInstance, nullptr);
        const auto font = reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT));
        for (HWND child = GetWindow(window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
            SendMessageW(child, WM_SETFONT, font, TRUE);
        SetFocus(prompt->edit);
        SendMessageW(prompt->edit, EM_SETSEL, 0, -1);
        return 0;
    }
    case WM_COMMAND:
        if (prompt && LOWORD(wparam) == IDOK) {
            wchar_t value[121]{};
            GetWindowTextW(prompt->edit, value, 121);
            std::wstring candidate(value);
            const auto first = candidate.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos) {
                MessageBoxW(window, L"Digite um nome para a conta.", L"MSK Autenticador", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            candidate = candidate.substr(first, candidate.find_last_not_of(L" \t\r\n") - first + 1);
            prompt->value = std::move(candidate);
            prompt->accepted = true;
            DestroyWindow(window);
            return 0;
        }
        if (LOWORD(wparam) == IDCANCEL) { DestroyWindow(window); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

bool prompt_account_name(State& state, std::wstring& value) {
    constexpr wchar_t prompt_class[] = L"MSKAuthenticatorNamePrompt";
    WNDCLASSW klass{};
    klass.hInstance = GetModuleHandleW(nullptr);
    klass.lpfnWndProc = name_prompt_proc;
    klass.lpszClassName = prompt_class;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    klass.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
    RegisterClassW(&klass);
    RECT owner{};
    GetWindowRect(state.window, &owner);
    const int x = owner.left + ((owner.right - owner.left) - 400) / 2;
    const int y = owner.top + ((owner.bottom - owner.top) - 175) / 2;
    NamePrompt prompt{value};
    HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, prompt_class, L"Renomear conta",
                                  WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                  x, y, 400, 175, state.window, nullptr, klass.hInstance, &prompt);
    if (!dialog) return false;
    BOOL dark = TRUE;
    DwmSetWindowAttribute(dialog, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    EnableWindow(state.window, FALSE);
    ShowWindow(dialog, SW_SHOW);
    MSG event{};
    while (IsWindow(dialog) && GetMessageW(&event, nullptr, 0, 0) > 0) {
        if (event.message == WM_KEYDOWN && event.wParam == VK_ESCAPE) {
            DestroyWindow(dialog);
            break;
        }
        if (event.message == WM_KEYDOWN && event.wParam == VK_RETURN) {
            SendMessageW(dialog, WM_COMMAND, IDOK, 0);
            continue;
        }
        TranslateMessage(&event);
        DispatchMessageW(&event);
    }
    EnableWindow(state.window, TRUE);
    SetForegroundWindow(state.window);
    if (prompt.accepted) value = std::move(prompt.value);
    return prompt.accepted;
}

void change_account(State& state, int index, int action) {
    if (index < 0 || index >= static_cast<int>(state.accounts.size())) return;
    std::wstring new_name = account_title(state.accounts[index]);
    if (action == edit_account && !prompt_account_name(state, new_name)) return;
    if (action == delete_account) {
        auto question = L"Excluir a conta \"" + new_name + L"\" deste computador?\nEssa ação não pode ser desfeita pelo aplicativo.";
        if (MessageBoxW(state.window, question.c_str(), L"Confirmar exclusão",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
    }
    auto full = auth::load_vault();
    if (index >= static_cast<int>(full.size()) ||
        full[index].name != state.accounts[index].name ||
        full[index].issuer != state.accounts[index].issuer) {
        throw std::runtime_error("A lista de contas mudou. Abra o aplicativo novamente.");
    }
    if (action == edit_account) full[index].issuer = new_name;
    else full.erase(full.begin() + index);
    auth::save_vault(full);
    state.accounts = std::move(full);
    if (!state.revealed) wipe_accounts(state);
    state.notice = action == edit_account ? L"Nome da conta atualizado." : L"Conta excluída deste computador.";
    InvalidateRect(state.window, nullptr, FALSE);
}

void reorder_accounts(State& state, int source, int target) {
    const int count = static_cast<int>(state.accounts.size());
    if (source < 0 || target < 0 || source >= count || target >= count || source == target) return;
    auto full = auth::load_vault();
    if (static_cast<int>(full.size()) != count) throw std::runtime_error("A lista de contas mudou.");
    for (int i = 0; i < count; ++i) {
        if (full[i].name != state.accounts[i].name || full[i].issuer != state.accounts[i].issuer)
            throw std::runtime_error("A lista de contas mudou.");
    }
    auto moved = std::move(full[source]);
    full.erase(full.begin() + source);
    full.insert(full.begin() + target, std::move(moved));
    auth::save_vault(full);
    state.accounts = std::move(full);
    if (!state.revealed) wipe_accounts(state);
    state.notice = L"Ordem das contas salva.";
    InvalidateRect(state.window, nullptr, FALSE);
}

void draw_button(Graphics& graphics, const State& state, int id, const std::wstring& text) {
    auto rect = button_rect(state, id);
    const bool active = state.hovered == id;
    const bool primary = id == 0;
    Color fill = primary ? (active ? rgb(122, 239, 200) : rgb(98, 223, 178))
                         : (active ? rgb(33, 51, 70) : rgb(24, 39, 56));
    Color border = primary ? rgb(98, 223, 178) : rgb(58, 79, 100);
    rounded(graphics, rect, scale(state, 9), fill, &border, scale(state, 1));
    if (state.focused == id) {
        RectF focus(rect.X - scale(state, 3), rect.Y - scale(state, 3),
                    rect.Width + scale(state, 6), rect.Height + scale(state, 6));
        Color focus_color = rgb(132, 227, 197);
        rounded(graphics, focus, scale(state, 11), Color(0, 0, 0, 0),
                &focus_color, scale(state, 1));
    }
    label(graphics, state, text, rect, 11, primary ? rgb(10, 39, 32) : rgb(225, 238, 247), true,
          StringAlignmentCenter);
}

std::wstring account_title(const auth::Account& account) {
    if (!account.issuer.empty()) return account.issuer;
    if (!account.name.empty()) return account.name;
    return L"Conta sem nome";
}

void draw_card(Graphics& graphics, const State& state, const auth::Account& account,
               float width, float y, int index, std::int64_t unix_seconds) {
    const float x = scale(state, 28);
    RectF bounds(x, y, width - scale(state, 56), card_height(state));
    Color border = state.dragging && index == state.drag_target
                       ? rgb(98, 223, 178) : rgb(43, 64, 83);
    rounded(graphics, bounds, scale(state, 11), rgb(20, 34, 49), &border, scale(state, 1));

    RectF avatar(x + scale(state, 12), y + scale(state, 12), scale(state, 39), scale(state, 39));
    Color avatar_border = rgb(46, 120, 106);
    rounded(graphics, avatar, scale(state, 10), rgb(25, 83, 76), &avatar_border, scale(state, 1));
    const auto title = account_title(account);
    std::wstring initial = title.substr(0, 1);
    label(graphics, state, initial, avatar, 18, rgb(145, 242, 204), true, StringAlignmentCenter);

    const float text_x = x + scale(state, 63);
    const float right_panel = scale(state, 190);
    const float left_width = std::max(scale(state, 100), bounds.Width - right_panel - scale(state, 72));
    label(graphics, state, title, RectF(text_x, y + scale(state, 8), left_width, scale(state, 24)),
          14, rgb(234, 244, 248), true);
    const auto secondary = account.issuer.empty() ? L"Autenticação de dois fatores" : account.name;
    label(graphics, state, secondary, RectF(text_x, y + scale(state, 30), left_width, scale(state, 20)),
          10, rgb(151, 174, 191));
    label(graphics, state, L"TOTP   ·   " + std::to_wstring(account.digits) + L" dígitos",
          RectF(text_x, y + scale(state, 58), left_width, scale(state, 18)),
          9, rgb(111, 203, 176), true);

    const float code_x = bounds.GetRight() - right_panel;
    std::wstring code = state.revealed ? auth::totp(account, unix_seconds)
                                       : (account.digits == 8 ? L"••••  ••••" : L"•••  •••");
    if (state.revealed) code.insert(code.size() / 2, L" ");
    label(graphics, state, code,
          RectF(code_x, y + scale(state, 8), right_panel - scale(state, 13), scale(state, 41)),
          23, state.revealed ? rgb(250, 253, 251) : rgb(104, 132, 149), true,
          StringAlignmentFar);
    if (state.revealed) SecureZeroMemory(code.data(), code.size() * sizeof(wchar_t));

    if (state.revealed) {
        const int remaining = account.period - static_cast<int>(unix_seconds % account.period);
        label(graphics, state, L"Renova em " + std::to_wstring(remaining) + L" s",
              RectF(code_x, y + scale(state, 51), right_panel - scale(state, 13), scale(state, 17)),
              9, rgb(153, 175, 190), false, StringAlignmentFar);
        RectF track(code_x + scale(state, 27), y + scale(state, 75),
                    right_panel - scale(state, 40), scale(state, 3));
        rounded(graphics, track, scale(state, 2), rgb(42, 62, 79));
        track.Width *= static_cast<float>(remaining) / account.period;
        rounded(graphics, track, scale(state, 2), rgb(99, 224, 179));
    } else {
        label(graphics, state, L"Protegido",
              RectF(code_x, y + scale(state, 50), right_panel - scale(state, 13), scale(state, 18)),
              9, rgb(131, 158, 173), false, StringAlignmentFar);
    }
    label(graphics, state, L"Renomear",
          action_bounds(state, width, index, edit_account),
          9, rgb(139, 204, 190), false, StringAlignmentCenter);
    label(graphics, state, L"Excluir",
          action_bounds(state, width, index, delete_account),
          9, rgb(214, 156, 157), false, StringAlignmentCenter);
}

void draw_tip(Graphics& graphics, const State& state, float width, float y) {
    const float x = scale(state, 36);
    RectF bounds(x, y, width - scale(state, 72), scale(state, 102));
    Color border = rgb(40, 59, 76);
    rounded(graphics, bounds, scale(state, 13), rgb(17, 30, 44), &border, scale(state, 1));
    label(graphics, state, L"Privacidade primeiro",
          RectF(x + scale(state, 20), y + scale(state, 13), bounds.Width - scale(state, 40), scale(state, 27)),
          14, rgb(217, 235, 239), true);
    label(graphics, state, L"Chaves protegidas pelo Windows  •  Sem servidor na internet  •  QR lido localmente",
          RectF(x + scale(state, 20), y + scale(state, 48), bounds.Width - scale(state, 40), scale(state, 26)),
          12, rgb(137, 163, 179));
}

void paint(HWND window, State& state, HDC hdc) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = std::max(1L, client.right), height = std::max(1L, client.bottom);
    Bitmap canvas(width, height, PixelFormat32bppPARGB);
    Graphics graphics(&canvas);
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    graphics.Clear(rgb(11, 19, 32));

    const float w = static_cast<float>(width), h = static_cast<float>(height);
    const float margin = scale(state, 28);
    line(graphics, rgb(37, 54, 71), margin, scale(state, 56), w - margin, scale(state, 56));
    RectF brand(scale(state, 28), scale(state, 12), scale(state, 31), scale(state, 31));
    if (state.icon) {
        Bitmap icon_image(state.icon);
        graphics.DrawImage(&icon_image, brand);
    }
    label(graphics, state, L"MSK  AUTENTICADOR",
          RectF(scale(state, 69), scale(state, 13), scale(state, 250), scale(state, 30)),
          13, rgb(224, 239, 242), true);
    RectF pill(w - scale(state, 158), scale(state, 17), scale(state, 130), scale(state, 23));
    rounded(graphics, pill, scale(state, 13), rgb(24, 57, 53));
    label(graphics, state, L"●  COFRE LOCAL", pill, 9, rgb(137, 229, 189), true,
          StringAlignmentCenter);

    RectF hero(margin, scale(state, 69), w - margin * 2, scale(state, 83));
    Color hero_border = rgb(45, 83, 99);
    rounded(graphics, hero, scale(state, 12), rgb(23, 50, 68), &hero_border, scale(state, 1));
    RectF strip(hero.X, hero.Y + scale(state, 13), scale(state, 3), hero.Height - scale(state, 26));
    rounded(graphics, strip, scale(state, 2), rgb(109, 226, 183));
    label(graphics, state, L"Seus códigos, sob seu controle",
          RectF(hero.X + scale(state, 20), hero.Y + scale(state, 10),
                hero.Width - scale(state, 40), scale(state, 33)),
          18, rgb(242, 250, 249), true);
    label(graphics, state, L"Autenticação local para suas contas. O cofre pertence ao seu usuário do Windows.",
          RectF(hero.X + scale(state, 20), hero.Y + scale(state, 45),
                hero.Width - scale(state, 40), scale(state, 20)),
          10, rgb(159, 191, 199));

    draw_button(graphics, state, 0, L"+  Importar QR");
    draw_button(graphics, state, 1, state.revealed ? L"Ocultar códigos" : L"Mostrar códigos");
    if (state.copied_toast_visible) {
        RectF toast(w - margin - scale(state, 112), scale(state, 167),
                    scale(state, 112), scale(state, 35));
        rounded(graphics, toast, scale(state, 9), rgb(25, 83, 76));
        label(graphics, state, L"Copiado", toast, 11, rgb(145, 242, 204), true,
              StringAlignmentCenter);
    }
    label(graphics, state, L"CONTAS  " + std::to_wstring(state.accounts.size()),
          RectF(margin, scale(state, 211), scale(state, 250), scale(state, 20)),
          10, rgb(136, 165, 183), true);

    const float list_top = content_top(state);
    const float list_bottom = h - scale(state, 48);
    const float view_height = std::max(0.0f, list_bottom - list_top);
    graphics.SetClip(RectF(0, list_top, w, view_height));
    if (state.accounts.empty()) {
        RectF empty(margin, list_top, w - margin * 2, scale(state, 126));
        Color border = rgb(46, 68, 84);
        rounded(graphics, empty, scale(state, 14), rgb(19, 32, 47), &border, scale(state, 1));
        label(graphics, state, L"Nenhuma conta cadastrada",
              RectF(empty.X + scale(state, 20), empty.Y + scale(state, 24),
                    empty.Width - scale(state, 40), scale(state, 30)),
              16, rgb(226, 240, 242), true);
        label(graphics, state, L"Use Importar QR para adicionar sua primeira conta.",
              RectF(empty.X + scale(state, 20), empty.Y + scale(state, 64),
                    empty.Width - scale(state, 40), scale(state, 25)),
              12, rgb(146, 172, 188));
    } else {
        const auto now = std::chrono::system_clock::now();
        const auto unix_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        for (int i = 0; i < static_cast<int>(state.accounts.size()); ++i) {
            float y = list_top + i * card_step(state) - state.scroll;
            if (y + card_height(state) < list_top || y > list_bottom) continue;
            draw_card(graphics, state, state.accounts[i], w, y, i, unix_seconds);
        }
        if (state.accounts.size() <= 2) {
            const float tip_y = list_top + state.accounts.size() * card_step(state) - state.scroll + scale(state, 2);
            if (tip_y + scale(state, 102) < list_bottom) draw_tip(graphics, state, w, tip_y);
        }
    }
    graphics.ResetClip();

    line(graphics, rgb(37, 54, 71), margin, h - scale(state, 42), w - margin, h - scale(state, 42));
    label(graphics, state, state.dragging ? L"◈  Solte o cartão na posição desejada."
                                          : L"◈  " + state.notice,
          RectF(margin, h - scale(state, 34), w - margin * 2, scale(state, 27)),
          10, rgb(143, 174, 188));
    Graphics screen(hdc);
    screen.DrawImage(&canvas, 0, 0);
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<State*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    try {
        switch (message) {
        case WM_CREATE: {
            auto owned = std::make_unique<State>();
            owned->window = window;
            owned->dpi = static_cast<float>(GetDpiForWindow(window)) / 96.0f;
            owned->accounts = auth::load_vault();
            wipe_accounts(*owned);
            owned->icon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101));
            SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(owned->icon));
            SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(owned->icon));
            BOOL dark = TRUE;
            DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
            SetTimer(window, timer_refresh, 1000, nullptr);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT paint_info{};
            HDC hdc = BeginPaint(window, &paint_info);
            if (state) paint(window, *state, hdc);
            EndPaint(window, &paint_info);
            return 0;
        }
        case WM_SIZE:
            if (state) {
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        case WM_DPICHANGED:
            if (state) {
                state->dpi = static_cast<float>(HIWORD(wparam)) / 96.0f;
                auto* suggested = reinterpret_cast<RECT*>(lparam);
                SetWindowPos(window, nullptr, suggested->left, suggested->top,
                             suggested->right - suggested->left, suggested->bottom - suggested->top,
                             SWP_NOZORDER | SWP_NOACTIVATE);
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
            const float dpi = state ? state->dpi : static_cast<float>(GetDpiForSystem()) / 96.0f;
            info->ptMinTrackSize = POINT{static_cast<LONG>(650 * dpi), static_cast<LONG>(420 * dpi)};
            return 0;
        }
        case WM_TIMER:
            if (state && wparam == timer_refresh) {
                if (state->copied_toast_visible &&
                    std::chrono::steady_clock::now() >= state->copied_toast_until) {
                    state->copied_toast_visible = false;
                    InvalidateRect(window, nullptr, FALSE);
                }
                if (!state->copied_code.empty() &&
                    std::chrono::steady_clock::now() - state->copied_at >= std::chrono::seconds(30)) {
                    clear_copied_code(*state);
                }
                if (state->revealed &&
                    std::chrono::steady_clock::now() - state->last_action > std::chrono::minutes(5)) hide(*state);
                else if (state->revealed) InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        case WM_MOUSEMOVE:
            if (state) {
                const float x = static_cast<float>(GET_X_LPARAM(lparam));
                const float y = static_cast<float>(GET_Y_LPARAM(lparam));
                if (state->drag_candidate >= 0 && (wparam & MK_LBUTTON)) {
                    const float distance = static_cast<float>(std::abs(GET_X_LPARAM(lparam) - state->drag_start.x) +
                                                               std::abs(GET_Y_LPARAM(lparam) - state->drag_start.y));
                    if (distance >= scale(*state, 7)) state->dragging = true;
                    if (state->dragging) {
                        RECT area{};
                        GetClientRect(window, &area);
                        const float bottom = static_cast<float>(area.bottom) - scale(*state, 48);
                        const float available = std::max(0.0f, bottom - content_top(*state));
                        const float maximum = std::max(0.0f,
                            state->accounts.size() * card_step(*state) - available);
                        if (y < content_top(*state) + scale(*state, 20))
                            state->scroll = std::max(0.0f, state->scroll - scale(*state, 12));
                        else if (y > bottom - scale(*state, 20))
                            state->scroll = std::min(maximum, state->scroll + scale(*state, 12));
                        const float position = y - content_top(*state) + state->scroll;
                        state->drag_target = std::clamp(static_cast<int>(position / card_step(*state)),
                                                         0, static_cast<int>(state->accounts.size()) - 1);
                        state->last_action = std::chrono::steady_clock::now();
                        SetCursor(LoadCursorW(nullptr, IDC_SIZEALL));
                        InvalidateRect(window, nullptr, FALSE);
                        return 0;
                    }
                }
                int hovered = inside(button_rect(*state, 0), x, y) ? 0 :
                              inside(button_rect(*state, 1), x, y) ? 1 : -1;
                if (hovered < 0) {
                    RECT area{};
                    GetClientRect(window, &area);
                    const float bottom = static_cast<float>(area.bottom) - scale(*state, 48);
                    if (y >= content_top(*state) && y < bottom) {
                        for (int i = 0; i < static_cast<int>(state->accounts.size()); ++i) {
                            if (inside(action_bounds(*state, static_cast<float>(area.right), i, edit_account), x, y) ||
                                inside(action_bounds(*state, static_cast<float>(area.right), i, delete_account), x, y) ||
                                (state->revealed && inside(code_bounds(*state, static_cast<float>(area.right), i), x, y))) {
                                hovered = 2;
                                break;
                            }
                        }
                    }
                }
                if (hovered != state->hovered) {
                    state->hovered = hovered;
                    InvalidateRect(window, nullptr, FALSE);
                }
            }
            return 0;
        case WM_SETCURSOR:
            if (state && state->dragging && LOWORD(lparam) == HTCLIENT) {
                SetCursor(LoadCursorW(nullptr, IDC_SIZEALL));
                return TRUE;
            }
            if (state && LOWORD(lparam) == HTCLIENT && state->hovered >= 0) {
                SetCursor(LoadCursorW(nullptr, IDC_HAND));
                return TRUE;
            }
            break;
        case WM_LBUTTONDOWN:
            if (state) {
                SetFocus(window);
                const float x = static_cast<float>(GET_X_LPARAM(lparam));
                const float y = static_cast<float>(GET_Y_LPARAM(lparam));
                for (int id = 0; id < 2; ++id) {
                    if (inside(button_rect(*state, id), x, y)) {
                        state->focused = id;
                        act(*state, id);
                        InvalidateRect(window, nullptr, FALSE);
                        return 0;
                    }
                }
                RECT area{};
                GetClientRect(window, &area);
                const float bottom = static_cast<float>(area.bottom) - scale(*state, 48);
                if (y >= content_top(*state) && y < bottom) {
                    for (int i = 0; i < static_cast<int>(state->accounts.size()); ++i) {
                        if (inside(action_bounds(*state, static_cast<float>(area.right), i, edit_account), x, y)) {
                            change_account(*state, i, edit_account);
                            return 0;
                        }
                        if (inside(action_bounds(*state, static_cast<float>(area.right), i, delete_account), x, y)) {
                            change_account(*state, i, delete_account);
                            return 0;
                        }
                    }
                    const int index = account_at(*state, static_cast<float>(area.right),
                                                 static_cast<float>(area.bottom), x, y);
                    if (index >= 0 && !(state->revealed &&
                        inside(code_bounds(*state, static_cast<float>(area.right), index), x, y))) {
                        state->drag_candidate = index;
                        state->drag_target = index;
                        state->drag_start = POINT{static_cast<LONG>(x), static_cast<LONG>(y)};
                        state->dragging = false;
                        SetCapture(window);
                        return 0;
                    }
                }
            }
            return 0;
        case WM_LBUTTONUP:
            if (state && state->drag_candidate >= 0) {
                const int source = state->drag_candidate;
                const int target = state->drag_target;
                const bool was_dragging = state->dragging;
                RECT area{};
                GetClientRect(window, &area);
                const float x = static_cast<float>(GET_X_LPARAM(lparam));
                const float y = static_cast<float>(GET_Y_LPARAM(lparam));
                const bool valid_drop = y >= content_top(*state) &&
                    y < static_cast<float>(area.bottom) - scale(*state, 48) &&
                    x >= scale(*state, 28) && x <= static_cast<float>(area.right) - scale(*state, 28);
                state->drag_candidate = -1;
                state->drag_target = -1;
                state->dragging = false;
                if (GetCapture() == window) ReleaseCapture();
                if (was_dragging && valid_drop) reorder_accounts(*state, source, target);
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        case WM_CAPTURECHANGED:
            if (state && state->drag_candidate >= 0) {
                state->drag_candidate = -1;
                state->drag_target = -1;
                state->dragging = false;
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        case WM_LBUTTONDBLCLK:
            if (state && state->revealed) {
                const float x = static_cast<float>(GET_X_LPARAM(lparam));
                const float y = static_cast<float>(GET_Y_LPARAM(lparam));
                RECT area{};
                GetClientRect(window, &area);
                const float bottom = static_cast<float>(area.bottom) - scale(*state, 48);
                if (y >= content_top(*state) && y < bottom) {
                    for (int i = 0; i < static_cast<int>(state->accounts.size()); ++i) {
                        if (inside(code_bounds(*state, static_cast<float>(area.right), i), x, y)) {
                            copy_account_code(*state, i);
                            return 0;
                        }
                    }
                }
            }
            return 0;
        case WM_KEYDOWN:
            if (state) {
                if (wparam == VK_TAB) {
                    state->focused = 1 - state->focused;
                    InvalidateRect(window, nullptr, FALSE);
                    return 0;
                }
                if (wparam == VK_RETURN || wparam == VK_SPACE) {
                    act(*state, state->focused);
                    return 0;
                }
                if (wparam == VK_ESCAPE) {
                    hide(*state);
                    return 0;
                }
            }
            break;
        case WM_MOUSEWHEEL:
            if (state) {
                RECT area{};
                GetClientRect(window, &area);
                const float available = std::max(0.0f, static_cast<float>(area.bottom) -
                                                    scale(*state, 48) - content_top(*state));
                const float total = state->accounts.size() * card_step(*state);
                const float maximum = std::max(0.0f, total - available);
                state->scroll = std::clamp(state->scroll -
                    static_cast<float>(GET_WHEEL_DELTA_WPARAM(wparam)) / WHEEL_DELTA * scale(*state, 72),
                    0.0f, maximum);
                state->last_action = std::chrono::steady_clock::now();
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;
        case WM_DESTROY:
            KillTimer(window, timer_refresh);
            if (state) {
                clear_copied_code(*state);
                delete state;
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            }
            PostQuitMessage(0);
            return 0;
        default:
            break;
        }
    } catch (const std::exception&) {
        MessageBoxW(window, L"Não foi possível concluir a operação. Verifique o QR ou o cofre protegido.",
                    L"MSK Autenticador", MB_OK | MB_ICONERROR);
        return message == WM_CREATE ? -1 : 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 1;
    GdiplusStartupInput startup{};
    ULONG_PTR gdiplus_token = 0;
    if (GdiplusStartup(&gdiplus_token, &startup, nullptr) != Ok) {
        CoUninitialize();
        return 1;
    }
    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = instance;
    klass.lpfnWndProc = window_proc;
    klass.style = CS_DBLCLKS;
    klass.lpszClassName = window_class;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    klass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(101));
    klass.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(101), IMAGE_ICON,
                                                  GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                                  LR_SHARED));
    RegisterClassExW(&klass);
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const float dpi = static_cast<float>(GetDpiForSystem()) / 96.0f;
    const int work_width = work.right - work.left;
    const int work_height = work.bottom - work.top;
    const int width = std::min(static_cast<int>(960 * dpi), work_width - static_cast<int>(28 * dpi));
    const int height = std::min(static_cast<int>(680 * dpi), work_height - static_cast<int>(28 * dpi));
    const int x = work.left + (work_width - width) / 2;
    const int y = work.top + (work_height - height) / 2;
    HWND window = CreateWindowExW(0, window_class, L"MSK Autenticador",
                                  WS_OVERLAPPEDWINDOW, x, y,
                                  width, height, nullptr, nullptr, instance, nullptr);
    if (!window) {
        GdiplusShutdown(gdiplus_token);
        CoUninitialize();
        return 1;
    }
    ShowWindow(window, show);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    GdiplusShutdown(gdiplus_token);
    CoUninitialize();
    return static_cast<int>(message.wParam);
}
