#pragma once

#include <string>
#include <vector>
#include <chrono>

struct DnsRecord {
    uint64_t plain_id;
    uint64_t flow_id;
    std::string timestamp; // Format: YYYY-MM-DD HH:MM:SS
    std::string src_ip;
    int src_port;
    std::string dst_ip;
    int dst_port;
    std::string traffic_type; // e.g., "plain-dns"

    std::string domain_name;
    int domain_name_len;
    std::string sld;  // Second Level Domain
    int subdomain_len;
    std::string tld;  // Top Level Domain
};

struct FlowRecord {
    uint64_t doh_id;
    std::string timestamp; // End time
    std::string start_ts;
    std::string end_ts;

    std::string client_ip;
    int client_port;
    std::string server_ip;
    int server_port;
    std::string traffic_type; // e.g., "doh"

    float duration;
    double flow_bytes_received;
    double flow_bytes_sent;
    float flow_received_rate;
    float flow_sent_rate;

    // Stat metrics (simplified for initial implementation)
    float packet_len_mean;
    float packet_len_std;
    float packet_time_mean;
    float packet_time_std;
};
