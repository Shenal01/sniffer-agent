#include "time_utils.h"
#include <iomanip>
#include <sstream>

namespace common {

std::string format_timestamp(std::chrono::system_clock::time_point tp) {
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm;
    gmtime_s(&tm, &t); // Windows-specific safe version for UTC

    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

    return ss.str();
}

} // namespace common
