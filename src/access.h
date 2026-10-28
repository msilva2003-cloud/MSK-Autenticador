#pragma once

namespace access {

// First launch asks the user to create a password. Later launches require it.
bool authenticate();

} // namespace access
