#include "DnsAbuseDatabaseExporter.h"
#include <iomanip>
#include <sstream>

std::string
DnsAbuseDatabaseExporter::generateSqlStatement(DnsAbuseFlowTracker &flow) {
  std::ostringstream sql;

  // Choose table based on port (53 -> plain, else -> doh)
  std::string table_name = (flow.src_port == 53 || flow.dst_port == 53)
                               ? "dns_all_plain"
                               : "dns_all_doh";

  // FIX: dns_all_plain uses src_ip/dst_ip, dns_all_doh uses client_ip/server_ip
  std::string ip_cols =
      (table_name == "dns_all_plain")
          ? "timestamp, src_ip, dst_ip, src_port, dst_port, "
          : "timestamp, client_ip, server_ip, client_port, server_port, ";

  sql << "INSERT INTO " << table_name << " (" << ip_cols
      << "traffic_type, "

      // Category 1: DNS Critical
      << "`features.dns_abuse.dns_amplification_factor`, "
      << "`features.dns_abuse.query_response_ratio`, "
      << "`features.dns_abuse.dns_any_query_ratio`, "
      << "`features.dns_abuse.dns_txt_query_ratio`, "
      << "`features.dns_abuse.dns_response_inconsistency`, "
      << "`features.dns_abuse.dns_queries_per_second`, "
      << "`features.dns_abuse.port_53_traffic_ratio`, "

      // Category 2: Flow Rates
      << "`features.dns_abuse.flow_bytes_per_sec`, "
      << "`features.dns_abuse.flow_packets_per_sec`, "
      << "`features.dns_abuse.fwd_packets_per_sec`, "
      << "`features.dns_abuse.bwd_packets_per_sec`, "

      // Category 3: Flow Statistics
      << "`features.dns_abuse.flow_duration`, "
      << "`features.dns_abuse.total_fwd_packets`, "
      << "`features.dns_abuse.total_bwd_packets`, "
      << "`features.dns_abuse.total_fwd_bytes`, "
      << "`features.dns_abuse.total_bwd_bytes`, "

      // Category 4: DNS Aggregates
      << "`features.dns_abuse.dns_total_queries`, "
      << "`features.dns_abuse.dns_total_responses`, "
      << "`features.dns_abuse.dns_response_size`, "

      // Category 5: Timing
      << "`features.dns_abuse.flow_iat_mean`, "
      << "`features.dns_abuse.flow_iat_std`, "
      << "`features.dns_abuse.flow_iat_min`, "
      << "`features.dns_abuse.flow_iat_max`, "
      << "`features.dns_abuse.fwd_iat_mean`, "
      << "`features.dns_abuse.bwd_iat_mean`, "

      // Category 6: Packet Sizes
      << "`features.dns_abuse.fwd_packet_length_mean`, "
      << "`features.dns_abuse.bwd_packet_length_mean`, "
      << "`features.dns_abuse.packet_size_std`, "
      << "`features.dns_abuse.flow_length_min`, "
      << "`features.dns_abuse.flow_length_max`, "
      << "`features.dns_abuse.average_packet_size`, "
      << "`features.dns_abuse.response_time_variance`, "

      // Category 7: Encrypted DNS
      << "`features.dns_abuse.large_packet_ratio`, "
      << "`features.dns_abuse.medium_packet_ratio`, "
      << "`features.dns_abuse.small_packet_ratio`, "
      << "`features.dns_abuse.sni_entropy`, "
      << "`features.dns_abuse.is_known_doh_server`, "
      << "`features.dns_abuse.encrypted_payload_size_variance`"
      << ") VALUES (";

  // Format all values
  // timestamp = NOW() for when the flow ended
  sql << "NOW(), "
      << "'" << flow.src_ip << "', "
      << "'" << flow.dst_ip << "', " << flow.src_port << ", " << flow.dst_port
      << ", "
      << "'DNS_ABUSE', ";

  // Set floating point precision
  sql << std::fixed << std::setprecision(4);

  // DNS Critical
  sql << flow.getDnsAmplificationFactor() << ", "
      << flow.getQueryResponseRatio() << ", " << flow.getDnsAnyQueryRatio()
      << ", " << flow.getDnsTxtQueryRatio() << ", "
      << flow.getDnsResponseInconsistency() << ", "
      << flow.getQueriesPerSecond() << ", " << flow.getPort53TrafficRatio()
      << ", ";

  // Flow Rates
  sql << flow.getFlowBytesPerSec() << ", " << flow.getFlowPacketsPerSec()
      << ", " << flow.getFwdPacketsPerSec() << ", "
      << flow.getBwdPacketsPerSec() << ", ";

  // Flow Stats
  sql << flow.getFlowDurationSec() * 1000.0 << ", " // milliseconds
      << flow.getTotalFwdPackets() << ", " << flow.getTotalBwdPackets() << ", "
      << flow.getTotalFwdBytes() << ", " << flow.getTotalBwdBytes() << ", ";

  // DNS Aggregates
  sql << flow.getDnsTotalQueries() << ", " << flow.getDnsTotalResponses()
      << ", " << flow.getDnsResponseSize() << ", ";

  // Timing
  sql << flow.getFlowIatMean() << ", " << flow.getFlowIatStd() << ", "
      << flow.getFlowIatMin() << ", " << flow.getFlowIatMax() << ", "
      << flow.getFwdIatMean() << ", " << flow.getBwdIatMean() << ", ";

  // Packet Sizes
  sql << flow.getFwdPacketLengthMean() << ", " << flow.getBwdPacketLengthMean()
      << ", " << flow.getPacketSizeStd() << ", " << flow.getFlowLengthMin()
      << ", " << flow.getFlowLengthMax() << ", " << flow.getAveragePacketSize()
      << ", " << flow.getResponseTimeVariance() << ", ";

  // Encrypted
  sql << flow.getLargePacketRatio() << ", " << flow.getMediumPacketRatio()
      << ", " << flow.getSmallPacketRatio() << ", " << flow.getSniEntropy()
      << ", " << flow.isKnownDoHServer() << ", "
      << flow.getEncryptedPayloadSizeVariance() << ");";

  return sql.str();
}
