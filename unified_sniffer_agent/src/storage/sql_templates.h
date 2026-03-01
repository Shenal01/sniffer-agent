#pragma once

namespace storage {

const char* INSERT_DNS_SQL = 
    "INSERT INTO dns_all_plain ("
    "timestamp, src_ip, src_port, dst_ip, dst_port, traffic_type, "
    "dns_domain_name, dns_domain_name_length, dns_second_level_domain, "
    "dns_subdomain_name_length, dns_top_level_domain"
    ") VALUES ";

const char* INSERT_FLOW_SQL = 
    "INSERT INTO dns_all_doh ("
    "timestamp, `flow_features.start_ts`, `flow_features.end_ts`, "
    "client_ip, client_port, server_ip, server_port, traffic_type, "
    "`flow_features.Duration`, `flow_features.FlowBytesReceived`, "
    "`flow_features.FlowBytesSent`, `flow_features.FlowReceivedRate`, "
    "`flow_features.FlowSentRate`, `flow_features.PacketLengthMean`"
    ") VALUES ";

} // namespace storage
