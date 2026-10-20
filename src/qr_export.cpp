#include "qr_export.h"

#include <CreateBarcode.h>
#include <WriteBarcode.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>

namespace qr_export {
namespace {

constexpr wchar_t dialog_class[] = L"MSKAuthenticatorQRExport";

std::string utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(),
                                        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::runtime_error("Nome invalido");
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(),
                        static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::string percent_encode(const std::string& text) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    for (unsigned char c : text) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
            output.push_back(static_cast<char>(c));
        else {
            output.push_back('%');
            output.push_back(hex[c >> 4]);
            output.push_back(hex[c & 15]);
        }
    }
    return output;
}

std::string base32(const std::vector<std::uint8_t>& bytes) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string output;
    unsigned int buffer = 0;
    int bits = 0;
    for (auto byte : bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output.push_back(alphabet[(buffer >> bits) & 31]);
        }
    }
    if (bits) output.push_back(alphabet[(buffer << (5 - bits)) & 31]);
    return output;
}

std::string uri(const auth::Account& account) {
    if (account.period != 30) throw std::runtime_error("Periodo incompatível com Google Authenticator");
    auto issuer = percent_encode(utf8(account.issuer));
    auto name = percent_encode(utf8(account.name));
    std::string output = "otpauth://totp/";
    if (!issuer.empty()) output += issuer + ":";
    output += name + "?secret=" + base32(account.secret);
    if (!issuer.empty()) output += "&issuer=" + issuer;
    output += "&algorithm=" + utf8(account.algorithm);
    output += "&digits=" + std::to_string(account.digits) + "&period=30";
    return output;
}

struct Dialog {
    ZXing::Image matrix;
    std::wstring title;
};

LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<Dialog*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_NCCREATE:
        SetWindowLongPtrW(window, GWLP_USERDATA,
            reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams));
        return TRUE;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(window, &ps);
        RECT whole{};
        GetClientRect(window, &whole);
        FillRect(dc, &whole, static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH)));
        SetBkMode(dc, TRANSPARENT);
        RECT heading{20, 15, whole.right - 20, 58};
        DrawTextW(dc, L"Leia com o Google Authenticator", -1, &heading,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        if (state && state->matrix.width() > 0) {
            const int size = std::min(whole.right - 42, whole.bottom - 140);
            const int unit = std::max(1, size / state->matrix.width());
            const int actual = unit * state->matrix.width();
            const int left = (whole.right - actual) / 2;
            const int top = 68;
            for (int y = 0; y < state->matrix.height(); ++y) {
                for (int x = 0; x < state->matrix.width(); ++x) {
                    if (*state->matrix.data(x, y) > 127) continue;
                    RECT pixel{left + x * unit, top + y * unit,
                               left + (x + 1) * unit, top + (y + 1) * unit};
                    FillRect(dc, &pixel, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
                }
            }
        }
        RECT caption{20, whole.bottom - 64, whole.right - 20, whole.bottom - 24};
        DrawTextW(dc, L"Este QR contém a chave secreta. Feche após importar.", -1, &caption,
                  DT_CENTER | DT_VCENTER | DT_WORDBREAK);
        EndPaint(window, &ps);
        return 0;
    }
    case WM_KEYDOWN:
        if (wparam == VK_ESCAPE) { DestroyWindow(window); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

void show(HWND parent, const auth::Account& account) {
    std::string data = uri(account);
    ZXing::Barcode barcode;
    try {
        barcode = ZXing::CreateBarcodeFromText(data,
            ZXing::CreatorOptions(ZXing::BarcodeFormat::QRCode));
    } catch (...) {
        SecureZeroMemory(data.data(), data.size());
        throw;
    }
    if (!barcode.isValid()) throw std::runtime_error("QR de exportacao indisponivel");
    auto matrix = ZXing::WriteBarcodeToImage(barcode);
    SecureZeroMemory(data.data(), data.size());
    Dialog state{std::move(matrix), account.issuer.empty() ? account.name : account.issuer};
    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = GetModuleHandleW(nullptr);
    klass.lpfnWndProc = procedure;
    klass.lpszClassName = dialog_class;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&klass);
    RECT owner{};
    GetWindowRect(parent, &owner);
    const int width = 430, height = 500;
    const auto title = L"Exportar QR — " + state.title;
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, dialog_class,
        title.c_str(), WS_CAPTION | WS_SYSMENU | WS_POPUP,
        owner.left + (owner.right - owner.left - width) / 2,
        owner.top + (owner.bottom - owner.top - height) / 2,
        width, height, parent, nullptr, GetModuleHandleW(nullptr), &state);
    if (!window) throw std::runtime_error("Janela de QR indisponivel");
    EnableWindow(parent, FALSE);
    ShowWindow(window, SW_SHOW);
    MSG message{};
    while (IsWindow(window) && GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    if (state.matrix.data())
        SecureZeroMemory(const_cast<std::uint8_t*>(state.matrix.data()),
                         state.matrix.height() * state.matrix.rowStride());
}

} // namespace qr_export
