#include "dns_parser.h"
#include <iostream>
#include <fmt/core.h>

namespace parsers {

bool DnsParser::parse(const uint8_t* payload, size_t length, DnsRecord& record) {
    if (length < 12) return false; // Min DNS header size

    // DNS Header
    // uint16_t id = (payload[0] << 8) | payload[1];
    uint16_t flags = (payload[2] << 8) | payload[3];
    uint16_t qdcount = (payload[4] << 8) | payload[5];

    bool qr = (flags >> 15) & 0x1;
    if (qr) return false; // We only care about queries for now (or handle responses later)
    if (qdcount == 0) return false;

    size_t offset = 12; // Start of Question section
    record.domain_name = decode_domain_name(payload, length, offset);
    
    if (record.domain_name.empty()) return false;

    // Remove trailing dot
    if (!record.domain_name.empty() && record.domain_name.back() == '.') {
        record.domain_name.pop_back();
    }

    record.domain_name_len = (int)record.domain_name.length();

    // Basic extraction of SLD and TLD
    size_t last_dot = record.domain_name.find_last_of('.');
    if (last_dot != std::string::npos) {
        record.tld = record.domain_name.substr(last_dot + 1);
        size_t second_last_dot = record.domain_name.find_last_of('.', last_dot - 1);
        if (second_last_dot != std::string::npos) {
            record.sld = record.domain_name.substr(second_last_dot + 1, last_dot - second_last_dot - 1);
            record.subdomain_len = (int)second_last_dot;
        } else {
            record.sld = record.domain_name.substr(0, last_dot);
            record.subdomain_len = 0;
        }
    } else {
        record.tld = record.domain_name;
        record.sld = "";
        record.subdomain_len = 0;
    }

    return true;
}

std::string DnsParser::decode_domain_name(const uint8_t* full_packet, size_t packet_len, size_t& offset) {
    std::string name = "";
    size_t current_offset = offset;
    bool jumped = false;
    size_t first_jump_offset = 0;
    int jumps = 0;
    const int MAX_JUMPS = 10;

    while (current_offset < packet_len) {
        uint8_t len = full_packet[current_offset];

        if (len == 0) {
            if (!jumped) offset = current_offset + 1;
            break;
        }

        if ((len & 0xC0) == 0xC0) { // Pointer
            if (current_offset + 1 >= packet_len) return "";
            if (!jumped) {
                first_jump_offset = current_offset + 2;
                jumped = true;
            }
            current_offset = ((len & 0x3F) << 8) | full_packet[current_offset + 1];
            jumps++;
            if (jumps > MAX_JUMPS) return ""; // Recursion limit
            continue;
        }

        current_offset++;
        if (current_offset + len > packet_len) return "";

        for (uint8_t i = 0; i < len; ++i) {
            name += (char)full_packet[current_offset + i];
        }
        name += ".";
        current_offset += len;

        if (!jumped) offset = current_offset;
    }

    if (jumped) offset = first_jump_offset;
    return name;
}

} // namespace parsers
