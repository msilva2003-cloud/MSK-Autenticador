#pragma once

#include "authenticator.h"
#include <windows.h>

namespace qr_export {

void show(HWND parent, const auth::Account& account);

} // namespace qr_export
