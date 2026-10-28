#pragma once

#include <windows.h>
#include <string>

namespace ui {

bool confirm_update(HWND owner, const std::wstring& version);

} // namespace ui
