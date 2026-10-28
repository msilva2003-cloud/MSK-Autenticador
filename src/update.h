#pragma once

#include <memory>
#include <mutex>
#include <string>

namespace update {

inline constexpr wchar_t current_version[] = L"0.1.8";

struct Result {
    std::mutex mutex;
    bool finished = false;
    bool available = false;
    bool failed = false;
    std::wstring installer;
    std::wstring expected_hash;
    std::wstring version;
};

bool installed_copy();
void check_in_background(const std::shared_ptr<Result>& result);
bool launch_verified(const Result& result);

} // namespace update
