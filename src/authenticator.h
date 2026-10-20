#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace auth {

struct Account {
    std::wstring name;
    std::wstring issuer;
    std::vector<std::uint8_t> secret;
    std::wstring algorithm = L"SHA1";
    int digits = 6;
    int period = 30;

    Account() = default;
    Account(const Account&) = delete;
    Account& operator=(const Account&) = delete;
    Account(Account&&) noexcept = default;
    Account& operator=(Account&&) noexcept = default;
    ~Account();
};

std::wstring vault_path();
std::vector<Account> load_vault();
void save_vault(const std::vector<Account>& accounts);
std::vector<Account> read_qr_image(const std::wstring& path);
std::vector<Account> read_qr_pixels(const std::uint8_t* pixels, int width, int height);
std::wstring totp(const Account& account, std::int64_t unix_seconds);
void wipe(std::vector<std::uint8_t>& data) noexcept;

} // namespace auth
