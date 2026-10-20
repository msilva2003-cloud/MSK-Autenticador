#pragma once

#include "authenticator.h"
#include <windows.h>
#include <vector>

namespace camera {

std::vector<auth::Account> scan(HWND parent);

} // namespace camera
