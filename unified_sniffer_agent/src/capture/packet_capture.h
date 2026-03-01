#pragma once

#include <string>

namespace capture {

class PacketDispatcher; // Forward declaration

bool start_capture(const std::string& adapter_name, PacketDispatcher& dispatcher);
void stop_capture();

} // namespace capture
