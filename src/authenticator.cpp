#include "authenticator.h"

#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <wincodec.h>
#include <wincrypt.h>
#include <wrl/client.h>

#include <ReadBarcode.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string_view>

namespace auth {
namespace {

constexpr std::array<std::uint8_t, 8> magic{'M','S','K','A','U','T','H','1'};
constexpr std::size_t max_file = 1024 * 1024;
using Bytes = std::vector<std::uint8_t>;
using Microsoft::WRL::ComPtr;

std::wstring wide(std::string_view text) {
    if (text.empty()) return {};
    if (text.size() > static_cast<std::size_t>(INT_MAX)) throw std::runtime_error("UTF-8 longo");
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                   static_cast<int>(text.size()), nullptr, 0);
    if (size == 0) throw std::runtime_error("UTF-8 invalido");
    std::wstring result(size, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                             static_cast<int>(text.size()), result.data(), size)) {
        throw std::runtime_error("UTF-8 invalido");
    }
    return result;
}

std::string utf8(std::wstring_view text) {
    if (text.empty()) return {};
    if (text.size() > static_cast<std::size_t>(INT_MAX)) throw std::runtime_error("Nome longo");
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                   static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size == 0) throw std::runtime_error("Texto invalido");
    std::string result(size, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                             static_cast<int>(text.size()), result.data(), size, nullptr, nullptr)) {
        throw std::runtime_error("Texto invalido");
    }
    return result;
}

void put_u32(Bytes& target, std::uint32_t value) {
    for (int n = 0; n < 4; ++n) target.push_back(static_cast<std::uint8_t>(value >> (8 * n)));
}

void put_text(Bytes& target, std::wstring_view value) {
    auto bytes = utf8(value);
    if (bytes.size() > 4096) throw std::runtime_error("Nome longo");
    put_u32(target, static_cast<std::uint32_t>(bytes.size()));
    target.insert(target.end(), bytes.begin(), bytes.end());
    SecureZeroMemory(bytes.data(), bytes.size());
}

struct Cursor {
    const Bytes& bytes;
    std::size_t position = 0;
    std::uint32_t u32() {
        if (bytes.size() - position < 4) throw std::runtime_error("Cofre incompleto");
        std::uint32_t result = 0;
        for (int n = 0; n < 4; ++n) result |= static_cast<std::uint32_t>(bytes[position++]) << (8 * n);
        return result;
    }
    Bytes take(std::size_t size) {
        if (size > bytes.size() - position) throw std::runtime_error("Cofre incompleto");
        Bytes result(bytes.begin() + position, bytes.begin() + position + size);
        position += size;
        return result;
    }
    std::wstring text() {
        auto size = u32();
        if (size > 4096) throw std::runtime_error("Nome longo");
        auto data = take(size);
        auto result = wide(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
        wipe(data);
        return result;
    }
};

Bytes protect(const Bytes& input, bool decrypt) {
    if (input.empty() || input.size() > std::numeric_limits<DWORD>::max())
        throw std::runtime_error("Dados invalidos");
    DATA_BLOB source{static_cast<DWORD>(input.size()), const_cast<BYTE*>(input.data())};
    DATA_BLOB result{};
    BOOL okay = decrypt
        ? CryptUnprotectData(&source, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &result)
        : CryptProtectData(&source, L"MSK Autenticador", nullptr, nullptr, nullptr,
                           CRYPTPROTECT_UI_FORBIDDEN, &result);
    if (!okay) throw std::runtime_error("Protecao Windows indisponivel");
    Bytes output(result.pbData, result.pbData + result.cbData);
    if (decrypt) SecureZeroMemory(result.pbData, result.cbData);
    LocalFree(result.pbData);
    return output;
}

std::string url_decode(std::string_view source) {
    std::string result;
    result.reserve(source.size());
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < source.size(); ++i) {
        if (source[i] == '%' && i + 2 < source.size()) {
            int high = digit(source[i + 1]), low = digit(source[i + 2]);
            if (high < 0 || low < 0) throw std::runtime_error("URI invalida");
            result.push_back(static_cast<char>(high * 16 + low));
            i += 2;
        } else if (source[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(source[i]);
        }
    }
    return result;
}

std::map<std::string, std::string> query(std::string_view uri) {
    std::map<std::string, std::string> values;
    auto question = uri.find('?');
    if (question == std::string_view::npos) return values;
    auto tail = uri.substr(question + 1);
    while (!tail.empty()) {
        auto amp = tail.find('&');
        auto part = tail.substr(0, amp);
        auto equals = part.find('=');
        if (equals != std::string_view::npos) {
            values.emplace(url_decode(part.substr(0, equals)), url_decode(part.substr(equals + 1)));
        }
        if (amp == std::string_view::npos) break;
        tail.remove_prefix(amp + 1);
    }
    return values;
}

Bytes base32(std::string_view value) {
    Bytes result;
    unsigned bits = 0, buffer = 0;
    for (char ch : value) {
        if (ch == '=' || ch == ' ') continue;
        char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        int digit = upper >= 'A' && upper <= 'Z' ? upper - 'A'
                  : upper >= '2' && upper <= '7' ? upper - '2' + 26 : -1;
        if (digit < 0) throw std::runtime_error("Chave Base32 invalida");
        buffer = (buffer << 5) | static_cast<unsigned>(digit);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<std::uint8_t>(buffer >> bits));
            buffer &= (1u << bits) - 1u;
        }
    }
    if (result.empty()) throw std::runtime_error("Chave vazia");
    return result;
}

Bytes base64(std::string text) {
    std::replace(text.begin(), text.end(), ' ', '+');
    DWORD size = 0;
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                              nullptr, &size, nullptr, nullptr)) {
        throw std::runtime_error("QR de exportacao invalido");
    }
    Bytes result(size);
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                              result.data(), &size, nullptr, nullptr)) {
        throw std::runtime_error("QR de exportacao invalido");
    }
    result.resize(size);
    SecureZeroMemory(text.data(), text.size());
    return result;
}

std::uint64_t varint(const Bytes& bytes, std::size_t& pos) {
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        if (pos >= bytes.size()) throw std::runtime_error("QR incompleto");
        auto byte = bytes[pos++];
        value |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
        if (!(byte & 0x80)) return value;
    }
    throw std::runtime_error("QR invalido");
}

struct ProtoField {
    int number;
    std::uint64_t integer = 0;
    Bytes data;
    bool has_data = false;
};

std::vector<ProtoField> fields(const Bytes& input) {
    std::vector<ProtoField> result;
    std::size_t pos = 0;
    while (pos < input.size()) {
        auto tag = varint(input, pos);
        int number = static_cast<int>(tag >> 3), wire = static_cast<int>(tag & 7);
        if (number <= 0) throw std::runtime_error("QR invalido");
        ProtoField field{number};
        if (wire == 0) field.integer = varint(input, pos);
        else if (wire == 2) {
            auto size = varint(input, pos);
            if (size > input.size() - pos) throw std::runtime_error("QR incompleto");
            field.data.assign(input.begin() + pos, input.begin() + pos + static_cast<std::size_t>(size));
            pos += static_cast<std::size_t>(size);
            field.has_data = true;
        } else if (wire == 1 || wire == 5) {
            auto size = wire == 1 ? 8u : 4u;
            if (size > input.size() - pos) throw std::runtime_error("QR incompleto");
            pos += size;
        } else throw std::runtime_error("Formato de QR invalido");
        result.push_back(std::move(field));
    }
    return result;
}

std::vector<Account> parse_migration(std::string_view uri) {
    auto values = query(uri);
    auto it = values.find("data");
    if (it == values.end()) throw std::runtime_error("QR sem contas");
    Bytes decoded = base64(it->second);
    auto outer = fields(decoded);
    std::vector<Account> accounts;
    for (const auto& field : outer) {
        if (field.number != 1 || !field.has_data) continue;
        auto inner = fields(field.data);
        Account account;
        int kind = 2, algorithm = 0, digits = 0;
        for (auto& entry : inner) {
            if (entry.number == 1 && entry.has_data) account.secret = std::move(entry.data);
            if (entry.number == 2 && entry.has_data)
                account.name = wide(std::string_view(reinterpret_cast<const char*>(entry.data.data()), entry.data.size()));
            if (entry.number == 3 && entry.has_data)
                account.issuer = wide(std::string_view(reinterpret_cast<const char*>(entry.data.data()), entry.data.size()));
            if (entry.number == 4) algorithm = static_cast<int>(entry.integer);
            if (entry.number == 5) digits = static_cast<int>(entry.integer);
            if (entry.number == 6) kind = static_cast<int>(entry.integer);
        }
        if (kind != 2 || account.secret.empty()) continue;
        if (algorithm == 0 || algorithm == 1) account.algorithm = L"SHA1";
        else if (algorithm == 2) account.algorithm = L"SHA256";
        else if (algorithm == 3) account.algorithm = L"SHA512";
        else continue;
        if (digits == 0 || digits == 1) account.digits = 6;
        else if (digits == 2) account.digits = 8;
        else continue;
        accounts.push_back(std::move(account));
    }
    wipe(decoded);
    if (accounts.empty()) throw std::runtime_error("Nenhuma conta TOTP compativel");
    return accounts;
}

Account parse_standard(std::string_view uri) {
    auto values = query(uri);
    auto secret = values.find("secret");
    if (secret == values.end()) throw std::runtime_error("QR sem chave");
    Account account;
    account.secret = base32(secret->second);
    auto start = std::string_view("otpauth://totp/").size();
    auto end = uri.find('?', start);
    account.name = wide(url_decode(uri.substr(start, end - start)));
    if (auto it = values.find("issuer"); it != values.end()) account.issuer = wide(it->second);
    if (auto it = values.find("algorithm"); it != values.end()) {
        std::string upper = it->second;
        std::transform(upper.begin(), upper.end(), upper.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        account.algorithm = wide(upper);
    }
    try {
        if (auto it = values.find("digits"); it != values.end()) account.digits = std::stoi(it->second);
        if (auto it = values.find("period"); it != values.end()) account.period = std::stoi(it->second);
    } catch (...) { throw std::runtime_error("Parametros TOTP invalidos"); }
    if ((account.digits != 6 && account.digits != 8) || account.period < 15 || account.period > 120 ||
        (account.algorithm != L"SHA1" && account.algorithm != L"SHA256" && account.algorithm != L"SHA512")) {
        throw std::runtime_error("Parametros TOTP nao suportados");
    }
    return account;
}

} // namespace

Account::~Account() { wipe(secret); }

void wipe(std::vector<std::uint8_t>& data) noexcept {
    if (!data.empty()) SecureZeroMemory(data.data(), data.size());
    data.clear();
}

std::wstring vault_path() {
    PWSTR folder = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &folder)))
        throw std::runtime_error("Pasta local indisponivel");
    std::wstring path(folder);
    CoTaskMemFree(folder);
    path += L"\\MSKAuthenticator";
    CreateDirectoryW(path.c_str(), nullptr);
    return path + L"\\vault.dpapi";
}

std::vector<Account> load_vault() {
    auto path = vault_path();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return {};
        throw std::runtime_error("Nao foi possivel abrir o cofre");
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > max_file) {
        CloseHandle(file);
        throw std::runtime_error("Tamanho de cofre invalido");
    }
    Bytes encrypted(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL okay = ReadFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &read, nullptr);
    CloseHandle(file);
    if (!okay || read != encrypted.size()) throw std::runtime_error("Leitura do cofre incompleta");
    Bytes plain = protect(encrypted, true);
    try {
        if (plain.size() < 12 || !std::equal(magic.begin(), magic.end(), plain.begin()))
            throw std::runtime_error("Formato de cofre invalido");
        Cursor cursor{plain, 8};
        auto count = cursor.u32();
        if (count > 200) throw std::runtime_error("Muitas contas no cofre");
        std::vector<Account> accounts;
        for (std::uint32_t index = 0; index < count; ++index) {
            Account account;
            account.name = cursor.text();
            account.issuer = cursor.text();
            auto algorithm = cursor.u32();
            account.algorithm = algorithm == 1 ? L"SHA1" : algorithm == 2 ? L"SHA256"
                              : algorithm == 3 ? L"SHA512" : L"";
            account.digits = static_cast<int>(cursor.u32());
            account.period = static_cast<int>(cursor.u32());
            auto secret_size = cursor.u32();
            if (secret_size < 8 || secret_size > 256 || account.algorithm.empty() ||
                (account.digits != 6 && account.digits != 8) ||
                account.period < 15 || account.period > 120) {
                throw std::runtime_error("Conta invalida no cofre");
            }
            account.secret = cursor.take(secret_size);
            accounts.push_back(std::move(account));
        }
        if (cursor.position != plain.size()) throw std::runtime_error("Dados extras no cofre");
        wipe(plain);
        return accounts;
    } catch (...) {
        wipe(plain);
        throw;
    }
}

void save_vault(const std::vector<Account>& accounts) {
    if (accounts.size() > 200) throw std::runtime_error("Limite de contas");
    Bytes plain(magic.begin(), magic.end());
    put_u32(plain, static_cast<std::uint32_t>(accounts.size()));
    for (const auto& account : accounts) {
        put_text(plain, account.name);
        put_text(plain, account.issuer);
        put_u32(plain, account.algorithm == L"SHA1" ? 1 : account.algorithm == L"SHA256" ? 2 : 3);
        put_u32(plain, static_cast<std::uint32_t>(account.digits));
        put_u32(plain, static_cast<std::uint32_t>(account.period));
        if (account.secret.empty() || account.secret.size() > 256) {
            wipe(plain);
            throw std::runtime_error("Chave invalida");
        }
        put_u32(plain, static_cast<std::uint32_t>(account.secret.size()));
        plain.insert(plain.end(), account.secret.begin(), account.secret.end());
    }
    Bytes encrypted;
    try { encrypted = protect(plain, false); }
    catch (...) { wipe(plain); throw; }
    wipe(plain);
    auto path = vault_path();
    auto temporary = path + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Nao foi possivel salvar o cofre");
    DWORD written = 0;
    BOOL okay = WriteFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &written, nullptr);
    if (okay) okay = FlushFileBuffers(file);
    CloseHandle(file);
    if (!okay || written != encrypted.size() ||
        !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("Nao foi possivel concluir o salvamento");
    }
}

std::vector<Account> read_qr_image(const std::wstring& path) {
    ComPtr<IWICImagingFactory> factory;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&factory)))) throw std::runtime_error("Leitor de imagem indisponivel");
    ComPtr<IWICBitmapDecoder> decoder;
    if (FAILED(factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                                   WICDecodeMetadataCacheOnLoad, &decoder)))
        throw std::runtime_error("Imagem do QR invalida");
    ComPtr<IWICBitmapFrameDecode> frame;
    if (FAILED(decoder->GetFrame(0, &frame))) throw std::runtime_error("Imagem sem quadro");
    UINT width = 0, height = 0;
    if (FAILED(frame->GetSize(&width, &height)) || width == 0 || height == 0 ||
        static_cast<std::uint64_t>(width) * height > 25'000'000) {
        throw std::runtime_error("Imagem do QR grande ou invalida");
    }
    ComPtr<IWICFormatConverter> converter;
    if (FAILED(factory->CreateFormatConverter(&converter)) ||
        FAILED(converter->Initialize(frame.Get(), GUID_WICPixelFormat32bppBGRA,
                                     WICBitmapDitherTypeNone, nullptr, 0, WICBitmapPaletteTypeCustom))) {
        throw std::runtime_error("Formato de imagem nao suportado");
    }
    Bytes pixels(static_cast<std::size_t>(width) * height * 4);
    if (FAILED(converter->CopyPixels(nullptr, width * 4, static_cast<UINT>(pixels.size()), pixels.data())))
        throw std::runtime_error("Leitura de pixels falhou");
    auto image = ZXing::ImageView(pixels.data(), static_cast<int>(width), static_cast<int>(height),
                                   ZXing::ImageFormat::BGRA);
    auto options = ZXing::ReaderOptions().setFormats(ZXing::BarcodeFormat::QRCode);
    auto codes = ZXing::ReadBarcodes(image, options);
    wipe(pixels);
    std::vector<Account> accounts;
    int recognized = 0;
    for (const auto& code : codes) {
        std::string uri = code.text();
        if (uri.starts_with("otpauth-migration://offline?")) {
            ++recognized;
            auto part = parse_migration(uri);
            for (auto& account : part) accounts.push_back(std::move(account));
        } else if (uri.starts_with("otpauth://totp/")) {
            ++recognized;
            accounts.push_back(parse_standard(uri));
        }
        SecureZeroMemory(uri.data(), uri.size());
    }
    if (recognized != 1 || accounts.empty()) throw std::runtime_error("Selecione uma imagem com um QR TOTP");
    return accounts;
}

std::wstring totp(const Account& account, std::int64_t unix_seconds) {
    if (account.period <= 0 || account.secret.empty()) throw std::runtime_error("Conta TOTP invalida");
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, account.algorithm.c_str(), nullptr,
                                   BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        throw std::runtime_error("Algoritmo TOTP indisponivel");
    auto close = [&]() {
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
    };
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0,
                         const_cast<PUCHAR>(account.secret.data()),
                         static_cast<ULONG>(account.secret.size()), 0) < 0) {
        close();
        throw std::runtime_error("Falha ao criar HMAC");
    }
    auto counter = static_cast<std::uint64_t>(unix_seconds / account.period);
    std::array<std::uint8_t, 8> message{};
    for (int i = 7; i >= 0; --i) { message[i] = static_cast<std::uint8_t>(counter); counter >>= 8; }
    std::array<std::uint8_t, 64> digest{};
    ULONG digest_size = account.algorithm == L"SHA1" ? 20 : account.algorithm == L"SHA256" ? 32 : 64;
    bool okay = BCryptHashData(hash, message.data(), static_cast<ULONG>(message.size()), 0) >= 0 &&
                BCryptFinishHash(hash, digest.data(), digest_size, 0) >= 0;
    close();
    if (!okay) throw std::runtime_error("Falha ao gerar TOTP");
    auto offset = digest[digest_size - 1] & 0x0F;
    std::uint32_t number = ((digest[offset] & 0x7F) << 24) |
                           (digest[offset + 1] << 16) |
                           (digest[offset + 2] << 8) | digest[offset + 3];
    std::uint32_t modulo = account.digits == 8 ? 100'000'000 : 1'000'000;
    number %= modulo;
    wchar_t buffer[9]{};
    swprintf_s(buffer, L"%0*u", account.digits, number);
    SecureZeroMemory(digest.data(), digest.size());
    return buffer;
}

} // namespace auth
