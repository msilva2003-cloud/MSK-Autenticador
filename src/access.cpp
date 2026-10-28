#include "access.h"

#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
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

struct Credential {
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 32> verifier{};
};

struct DialogState {
    HWND password = nullptr;
    HWND confirmation = nullptr;
    bool setup = false;
    bool accepted = false;
    bool finished = false;
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
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
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

bool verify_or_create(const std::wstring& password, const std::wstring& confirmation, bool setup) {
    if (password.size() < 8) {
        MessageBoxW(nullptr, L"Use uma senha com pelo menos 8 caracteres.", L"MSK Autenticador",
                    MB_OK | MB_ICONINFORMATION);
        return false;
    }
    Credential credential;
    if (setup) {
        if (password != confirmation) {
            MessageBoxW(nullptr, L"As senhas não coincidem.", L"MSK Autenticador",
                        MB_OK | MB_ICONINFORMATION);
            return false;
        }
        if (BCryptGenRandom(nullptr, credential.salt.data(), static_cast<ULONG>(credential.salt.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !derive(password, credential.salt, credential.verifier))
            throw std::runtime_error("Nao foi possivel preparar a senha");
        save(credential);
        SecureZeroMemory(credential.verifier.data(), credential.verifier.size());
        return true;
    }
    if (!load(credential)) return false;
    std::array<std::uint8_t, 32> candidate{};
    const bool okay = derive(password, credential.salt, candidate);
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < candidate.size(); ++i)
        difference |= candidate[i] ^ credential.verifier[i];
    const bool matches = okay && difference == 0;
    SecureZeroMemory(candidate.data(), candidate.size());
    SecureZeroMemory(credential.verifier.data(), credential.verifier.size());
    if (!matches)
        MessageBoxW(nullptr, L"Senha incorreta.", L"MSK Autenticador", MB_OK | MB_ICONWARNING);
    return matches;
}

LRESULT CALLBACK dialog_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<DialogState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_CREATE) {
        auto* creation = reinterpret_cast<CREATESTRUCTW*>(lparam);
        state = static_cast<DialogState*>(creation->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        const auto font = reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT));
        const float dpi = static_cast<float>(GetDpiForSystem()) / 96.0f;
        const auto px = [dpi](int value) { return static_cast<int>(value * dpi + 0.5f); };
        const wchar_t* instruction = state->setup ? L"Crie uma senha para abrir o módulo (mínimo de 8 caracteres):"
                                                  : L"Digite sua senha para abrir o módulo:";
        CreateWindowExW(0, L"STATIC", instruction, WS_CHILD | WS_VISIBLE,
                        px(24), px(20), px(372), px(state->setup ? 44 : 28),
                        window, nullptr, creation->hInstance, nullptr);
        state->password = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            px(24), px(state->setup ? 74 : 66), px(372), px(30), window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(password_id)), creation->hInstance, nullptr);
        SendMessageW(state->password, EM_LIMITTEXT, 128, 0);
        if (state->setup) {
            CreateWindowExW(0, L"STATIC", L"Confirme a senha:", WS_CHILD | WS_VISIBLE,
                            px(24), px(120), px(372), px(22), window, nullptr, creation->hInstance, nullptr);
            state->confirmation = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                px(24), px(146), px(372), px(30), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(confirmation_id)), creation->hInstance, nullptr);
            SendMessageW(state->confirmation, EM_LIMITTEXT, 128, 0);
        }
        const int button_y = px(state->setup ? 204 : 119);
        const int button_h = px(34);
        CreateWindowExW(0, L"BUTTON", state->setup ? L"Criar senha" : L"Desbloquear",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            px(186), button_y, px(110), button_h, window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)), creation->hInstance, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Sair", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            px(306), button_y, px(90), button_h, window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)), creation->hInstance, nullptr);
        for (HWND child = GetWindow(window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
            SendMessageW(child, WM_SETFONT, font, TRUE);
        SetFocus(state->password);
        return FALSE;
    }
    if (message == WM_COMMAND && state) {
        if (LOWORD(wparam) == IDCANCEL) {
            state->finished = true;
            DestroyWindow(window);
            return 0;
        }
        if (LOWORD(wparam) == IDOK) {
            wchar_t password[256]{}, confirmation[256]{};
            GetWindowTextW(state->password, password, static_cast<int>(std::size(password)));
            if (state->confirmation)
                GetWindowTextW(state->confirmation, confirmation, static_cast<int>(std::size(confirmation)));
            try {
                state->accepted = verify_or_create(password, confirmation, state->setup);
            } catch (...) {
                MessageBoxW(window, L"Não foi possível validar ou salvar a senha.", L"MSK Autenticador",
                            MB_OK | MB_ICONERROR);
            }
            SecureZeroMemory(password, sizeof(password));
            SecureZeroMemory(confirmation, sizeof(confirmation));
            if (state->accepted) {
                state->finished = true;
                SetWindowTextW(state->password, L"");
                if (state->confirmation) SetWindowTextW(state->confirmation, L"");
                DestroyWindow(window);
            } else {
                SetWindowTextW(state->password, L"");
                if (state->confirmation) SetWindowTextW(state->confirmation, L"");
                SetFocus(state->password);
            }
            return 0;
        }
    }
    if (message == WM_CTLCOLORSTATIC) {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
        SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
    }
    if (message == WM_CLOSE && state) {
        state->finished = true;
        DestroyWindow(window);
        return 0;
    }
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
    klass.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
    RegisterClassW(&klass);
    DialogState state;
    state.setup = setup;
    const float dpi = static_cast<float>(GetDpiForSystem()) / 96.0f;
    const int width = static_cast<int>(440 * dpi + 0.5f);
    const int height = static_cast<int>((setup ? 300 : 225) * dpi + 0.5f);
    HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, dialog_class,
        setup ? L"Criar senha — MSK Autenticador" : L"Desbloquear — MSK Autenticador",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, width, height,
        nullptr, nullptr, klass.hInstance, &state);
    if (!dialog) return false;
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int x = work.left + ((work.right - work.left) - width) / 2;
    const int y = work.top + ((work.bottom - work.top) - height) / 2;
    SetWindowPos(dialog, HWND_TOPMOST, x, y, width, height, SWP_NOACTIVATE);
    ShowWindow(dialog, SW_SHOW);
    UpdateWindow(dialog);
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
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return state.accepted;
}

} // namespace access
