#ifndef DNS_ABUSE_FLOW_TRACKER_H
#define DNS_ABUSE_FLOW_TRACKER_H

#include "BasicStats.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

/**
 * Port of Flow.java & DnsFeatureExtractor.java
 * Tracks all 44 AI features accurately.
 */
class DnsAbuseFlowTracker {
public:
  std::string src_ip;
  std::string dst_ip;
  int src_port;
  int dst_port;
  std::string protocol;

private:
  // Flow Timing
  long start_time_ms;
  long last_packet_time_ms;
  long flow_duration_ms;

  // Traffic volume
  long fwd_count;
  long bwd_count;

  // Basic Stats for packets & IAT
  BasicStats flow_length_stats;
  BasicStats fwd_payload_stats;
  BasicStats bwd_payload_stats;
  BasicStats flow_iat_stats;
  BasicStats fwd_iat_stats;
  BasicStats bwd_iat_stats;

  long last_fwd_time_ms;
  long last_bwd_time_ms;

  // DNS Extractor Fields (Ported from DnsFeatureExtractor.java)
  bool is_dns;
  long dns_query_packet_count;
  long dns_response_packet_count;
  long total_question_count;
  long total_answer_count;
  long dns_any_count;
  long dns_txt_count;
  long total_query_bytes;
  long total_response_bytes;

  // Query tracking for variance
  std::map<uint16_t, long> pending_queries;
  double response_time_sum;
  double response_time_sq_sum;
  long response_time_count;

  // TLS specific
  bool has_tls;
  std::string sni_hostname;
  BasicStats tls_payload_stats;

  // Encrypted DNS packet size categorization
  long small_packet_count;
  long medium_packet_count;
  long large_packet_count;

public:
  DnsAbuseFlowTracker(std::string src, std::string dst, int sport, int dport,
                      std::string proto);

  // Main extraction method analogous to Java's processPacket / addPacket
  void addPacket(const uint8_t *payload, size_t length, long timestamp_ms,
                 bool is_forward);

  // Private helpers
  void processDnsPacket(const uint8_t *payload, size_t length,
                        long timestamp_ms);
  void processTlsPacket(const uint8_t *payload, size_t length);
  std::string extractSni(const uint8_t *payload, size_t length);

  long getLastPacketTimeMs();

  // --- Feature Getters (Output exactly 44 features) ---
  double getFlowDurationSec();

  // Category 1: DNS Critical
  double getDnsAmplificationFactor();
  double getQueryResponseRatio();
  double getDnsAnyQueryRatio();
  double getDnsTxtQueryRatio();
  long getDnsResponseInconsistency();
  double getQueriesPerSecond();
  double getPort53TrafficRatio();

  // Category 2: Flow Rates
  double getFlowBytesPerSec();
  double getFlowPacketsPerSec();
  double getFwdPacketsPerSec();
  double getBwdPacketsPerSec();

  // Category 3: Flow Statistics
  // (Duration already covered)
  long getTotalFwdPackets();
  long getTotalBwdPackets();
  double getTotalFwdBytes();
  double getTotalBwdBytes();

  // Category 4: DNS Aggregates
  long getDnsTotalQueries();
  long getDnsTotalResponses();
  long getDnsResponseSize();

  // Category 5: Timing
  double getFlowIatMean();
  double getFlowIatStd();
  double getFlowIatMin();
  double getFlowIatMax();
  double getFwdIatMean();
  double getBwdIatMean();

  // Category 6: Packet Sizes
  double getFwdPacketLengthMean();
  double getBwdPacketLengthMean();
  double getPacketSizeStd();
  double getFlowLengthMin();
  double getFlowLengthMax();

  // Category 7: Advanced
  double getResponseTimeVariance();
  double getAveragePacketSize();

  // Category 8: Encrypted DNS
  double getLargePacketRatio();
  double getMediumPacketRatio();
  double getSmallPacketRatio();
  double getSniEntropy();
  int isKnownDoHServer();
  double getEncryptedPayloadSizeVariance();

  // C++ utility: Calculate Shannon Entropy of a string
  double calculateShannonEntropy(const std::string &str);
};

#endif // DNS_ABUSE_FLOW_TRACKER_H
