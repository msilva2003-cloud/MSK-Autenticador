#include "update.h"

#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <shellapi.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace update {
namespace {

constexpr wchar_t api_url[] =
    L"https://api.github.com/repos/msilva2003-cloud/MSK-Autenticador/releases/latest";
constexpr wchar_t release_root[] =
    L"https://github.com/msilva2003-cloud/MSK-Autenticador/releases/download/";
constexpr std::size_t max_metadata = 1024 * 1024;
constexpr std::size_t max_installer = 50 * 1024 * 1024;

struct InternetHandle {
    HINTERNET value = nullptr;
    ~InternetHandle() { if (value) WinHttpCloseHandle(value); }
    operator HINTERNET() const { return value; }
};

std::wstring local_app_data() {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw)))
        throw std::runtime_error("LocalAppData indisponivel");
    std::wstring path(raw);
    CoTaskMemFree(raw);
    return path;
}

std::wstring executable_path() {
    std::wstring path(32768, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size >= path.size()) throw std::runtime_error("Caminho invalido");
    path.resize(size);
    return path;
}

std::vector<std::uint8_t> fetch(const std::wstring& url, std::size_t limit) {
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS)
        throw std::runtime_error("Endereco de atualizacao invalido");
    const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    const std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
    InternetHandle session{WinHttpOpen(L"MSKAuthenticator/0.1.6", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session) throw std::runtime_error("Rede indisponivel");
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 15000);
    InternetHandle connection{WinHttpConnect(session, host.c_str(), parts.nPort, 0)};
    if (!connection) throw std::runtime_error("Conexao indisponivel");
    InternetHandle request{WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr,
                                               WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               WINHTTP_FLAG_SECURE)};
    if (!request) throw std::runtime_error("Requisicao indisponivel");
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request, nullptr))
        throw std::runtime_error("Download indisponivel");
    DWORD status = 0, length = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &length, WINHTTP_NO_HEADER_INDEX) ||
        status != 200) throw std::runtime_error("Resposta de atualizacao invalida");
    std::vector<std::uint8_t> data;
    std::array<std::uint8_t, 32768> chunk{};
    for (;;) {
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), static_cast<DWORD>(chunk.size()), &read))
            throw std::runtime_error("Download incompleto");
        if (!read) break;
        if (read > limit - data.size()) throw std::runtime_error("Download grande demais");
        data.insert(data.end(), chunk.begin(), chunk.begin() + read);
    }
    return data;
}

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("SHA-256 indisponivel");
    std::array<std::uint8_t, 32> digest{};
    const auto status = BCryptHash(algorithm, nullptr, 0,
        const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) throw std::runtime_error("Falha no SHA-256");
    return digest;
}

std::wstring hex_hash(const std::vector<std::uint8_t>& data) {
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring result;
    result.reserve(64);
    for (auto byte : sha256(data)) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::wstring latest_version(const std::vector<std::uint8_t>& data) {
    std::string json(data.begin(), data.end());
    auto start = json.find("\"tag_name\"");
    if (start == std::string::npos) return {};
    start = json.find(':', start + 10);
    if (start == std::string::npos) return {};
    start = json.find('"', start);
    if (start == std::string::npos) return {};
    auto end = json.find('"', ++start);
    if (end == std::string::npos || end - start > 24) return {};
    const auto tag = json.substr(start, end - start);
    if (tag.size() < 2 || tag[0] != 'v' ||
        !std::all_of(tag.begin() + 1, tag.end(), [](unsigned char c) {
            return std::isdigit(c) || c == '.';
        })) return {};
    return std::wstring(tag.begin() + 1, tag.end());
}

std::array<int, 3> version_parts(const std::wstring& value) {
    std::array<int, 3> parts{};
    std::size_t cursor = 0;
    for (auto& part : parts) {
        auto end = value.find(L'.', cursor);
        if (end == std::wstring::npos) end = value.size();
        if (end == cursor || end - cursor > 5) return {};
        for (auto index = cursor; index < end; ++index) {
            if (value[index] < L'0' || value[index] > L'9') return {};
            part = part * 10 + (value[index] - L'0');
        }
        cursor = end + 1;
    }
    if (cursor != value.size() + 1) return {};
    return parts;
}

std::wstring installer_name(const std::wstring& version) {
    return L"MSK-Autenticador-Setup-" + version + L"-windows-x64.exe";
}

std::wstring expected_hash(const std::vector<std::uint8_t>& data,
                           const std::wstring& filename) {
    std::string line(data.begin(), data.end());
    if (line.size() > 512 || line.size() < 67) return {};
    std::wstring hash;
    for (std::size_t i = 0; i < 64; ++i) {
        const auto c = static_cast<unsigned char>(line[i]);
        if (!std::isxdigit(c)) return {};
        hash.push_back(static_cast<wchar_t>(std::toupper(c)));
    }
    if (line[64] != ' ' || line[65] != ' ') return {};
    const std::string name(filename.begin(), filename.end());
    if (line.substr(66, name.size()) != name) return {};
    if (line.size() > 66 + name.size() && line[66 + name.size()] != '\n' &&
        line[66 + name.size()] != '\r') return {};
    return hash;
}

std::wstring save_installer(const std::wstring& version,
                            const std::vector<std::uint8_t>& data) {
    auto base = local_app_data() + L"\\MSKAuthenticator";
    if (!CreateDirectoryW(base.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        throw std::runtime_error("Pasta de atualizacao indisponivel");
    base += L"\\updates";
    if (!CreateDirectoryW(base.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        throw std::runtime_error("Pasta de atualizacao indisponivel");
    auto path = base + L"\\" + installer_name(version);
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Arquivo de atualizacao indisponivel");
    DWORD written = 0;
    const BOOL okay = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    const BOOL flushed = okay && FlushFileBuffers(file);
    CloseHandle(file);
    if (!okay || !flushed || written != data.size()) {
        DeleteFileW(path.c_str());
        throw std::runtime_error("Falha ao guardar atualizacao");
    }
    return path;
}

} // namespace

bool installed_copy() {
    try {
        auto expected = local_app_data() + L"\\Programs\\MSK Autenticador\\MSKAuthenticator.exe";
        return _wcsicmp(executable_path().c_str(), expected.c_str()) == 0;
    } catch (...) { return false; }
}

void check_in_background(const std::shared_ptr<Result>& result) {
    std::thread([result] {
        try {
            const auto latest = latest_version(fetch(api_url, max_metadata));
            if (latest.empty() || version_parts(latest) <= version_parts(current_version)) {
                std::lock_guard lock(result->mutex);
                result->finished = true;
                return;
            }
            const auto filename = installer_name(latest);
            const auto root = std::wstring(release_root) + L"v" + latest + L"/";
            const auto hash = expected_hash(fetch(root + filename + L".sha256", 512), filename);
            if (hash.empty()) throw std::runtime_error("Checksum invalido");
            const auto bytes = fetch(root + filename, max_installer);
            if (bytes.empty() || hex_hash(bytes) != hash)
                throw std::runtime_error("Checksum diferente");
            const auto path = save_installer(latest, bytes);
            std::lock_guard lock(result->mutex);
            result->installer = path;
            result->expected_hash = hash;
            result->version = latest;
            result->available = true;
            result->finished = true;
        } catch (...) {
            std::lock_guard lock(result->mutex);
            result->failed = true;
            result->finished = true;
        }
    }).detach();
}

bool launch_verified(const Result& result) {
    try {
        if (result.installer.empty() || result.expected_hash.empty()) return false;
        HANDLE file = CreateFileW(result.installer.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > max_installer) {
            CloseHandle(file);
            return false;
        }
        std::vector<std::uint8_t> data(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        const BOOL okay = ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
        CloseHandle(file);
        if (!okay || read != data.size() || hex_hash(data) != result.expected_hash) return false;
        SHELLEXECUTEINFOW launch{};
        launch.cbSize = sizeof(launch);
        launch.fMask = SEE_MASK_NOCLOSEPROCESS;
        launch.lpFile = result.installer.c_str();
        launch.lpParameters = L"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /AUTOUPDATE=1";
        launch.nShow = SW_HIDE;
        if (!ShellExecuteExW(&launch)) return false;
        if (launch.hProcess) CloseHandle(launch.hProcess);
        return true;
    } catch (...) { return false; }
}

} // namespace update
