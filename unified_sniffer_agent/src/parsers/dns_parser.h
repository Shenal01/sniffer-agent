#pragma once

#include "common/types.h"
#include <cstdint>
#include <string>

namespace parsers {

class DnsParser {
public:
    static bool parse(const uint8_t* payload, size_t length, DnsRecord& record);

private:
    static std::string decode_domain_name(const uint8_t* full_packet, size_t packet_len, size_t& offset);
};

} // namespace parsers
