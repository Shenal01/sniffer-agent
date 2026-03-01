#pragma once

#include <string>
#include <chrono>

namespace common {

std::string format_timestamp(std::chrono::system_clock::time_point tp);

} // namespace common
