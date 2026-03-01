#include "packet_dispatcher.h"
#include "common/time_utils.h"
#include <fmt/core.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace capture {

PacketDispatcher::PacketDispatcher(storage::DbWriter& db_writer) 
    : db_writer_(db_writer), 
      flow_tracker_([this](const FlowRecord& record) { 
          // fmt::print("[Flow Completed] {} -> {} | Duration: {:.2f}s | Bytes: {}\n", 
          //            record.client_ip, record.server_ip, record.duration, record.flow_bytes_received + record.flow_bytes_sent);
          db_writer_.queue_flow(record); 
      }) {}

void PacketDispatcher::handle_packet(const struct pcap_pkthdr* header, const uint8_t* packet) {
    // 1. Ethernet Header
    constexpr int ETHERNET_HEADER_LEN = 14;
    
    // 2. IP Header
    const uint8_t* ip_packet = packet + ETHERNET_HEADER_LEN;
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    
    if (version != 4) return; // IPv4 only for now

    int ip_header_len = (ip_packet[0] & 0x0F) * 4;
    uint8_t protocol = ip_packet[9];

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_packet + 12, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, ip_packet + 16, dst_ip, INET_ADDRSTRLEN);

    // 3. Transport Layer
    if (protocol == IPPROTO_TCP) {
        const uint8_t* tcp_packet = ip_packet + ip_header_len;
        uint16_t src_port = ntohs(*(uint16_t*)tcp_packet);
        uint16_t dst_port = ntohs(*(uint16_t*)(tcp_packet + 2));
        int tcp_header_len = ((tcp_packet[12] >> 4) & 0x0F) * 4;

        if (src_port == 443 || dst_port == 443) {
            // Flow Tracking for DoH
            uint8_t flags = tcp_packet[13];
            flow_tracker_.process_packet(src_ip, src_port, dst_ip, dst_port, header->len, flags);
        } else if (src_port == 53 || dst_port == 53) {

            // DNS over TCP (simplified: we offset to the DNS payload which has a 2-byte length prefix)
            const uint8_t* dns_payload = tcp_packet + tcp_header_len;
            size_t payload_len = header->len - (ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len);
            
            if (payload_len > 2) {
                DnsRecord record;
                if (parsers::DnsParser::parse(dns_payload + 2, payload_len - 2, record)) {
                    record.timestamp = common::format_timestamp(std::chrono::system_clock::now());
                    // fmt::print("[DNS Query] {} -> {}: {}\n", src_ip, dst_ip, record.domain_name);
                    record.src_ip = src_ip;
                    record.src_port = src_port;
                    record.dst_ip = dst_ip;
                    record.dst_port = dst_port;
                    record.traffic_type = "plain-dns-tcp";
                    db_writer_.queue_dns(record);
                }
            }
        }
    } else if (protocol == IPPROTO_UDP) {
        const uint8_t* udp_packet = ip_packet + ip_header_len;
        uint16_t src_port = ntohs(*(uint16_t*)udp_packet);
        uint16_t dst_port = ntohs(*(uint16_t*)(udp_packet + 2));
        
        if (src_port == 53 || dst_port == 53) {
            const uint8_t* dns_payload = udp_packet + 8;
            size_t payload_len = header->len - (ETHERNET_HEADER_LEN + ip_header_len + 8);

            DnsRecord record;
            if (parsers::DnsParser::parse(dns_payload, payload_len, record)) {
                record.timestamp = common::format_timestamp(std::chrono::system_clock::now());
                // fmt::print("[DNS Query] {} -> {}: {}\n", src_ip, dst_ip, record.domain_name);
                record.src_ip = src_ip;
                record.src_port = src_port;
                record.dst_ip = dst_ip;
                record.dst_port = dst_port;
                record.traffic_type = "plain-dns-udp";
                db_writer_.queue_dns(record);
            }
        }
    }
}

void PacketDispatcher::cleanup_flows() {
    flow_tracker_.cleanup_idle_flows();
}

} // namespace capture
