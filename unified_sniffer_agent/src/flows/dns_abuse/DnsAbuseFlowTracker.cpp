#include "DnsAbuseFlowTracker.h"
#include "DoHServerDatabase.h"
#include <algorithm>
#include <cmath>
#include <iostream>

DnsAbuseFlowTracker::DnsAbuseFlowTracker(std::string src, std::string dst,
                                         int sport, int dport,
                                         std::string proto)
    : src_ip(std::move(src)), dst_ip(std::move(dst)), src_port(sport),
      dst_port(dport), protocol(std::move(proto)), start_time_ms(0),
      last_packet_time_ms(0), flow_duration_ms(0), fwd_count(0), bwd_count(0),
      last_fwd_time_ms(0), last_bwd_time_ms(0), is_dns(false),
      dns_query_packet_count(0), dns_response_packet_count(0),
      total_question_count(0), total_answer_count(0), dns_any_count(0),
      dns_txt_count(0), total_query_bytes(0), total_response_bytes(0),
      response_time_sum(0.0), response_time_sq_sum(0.0), response_time_count(0),
      has_tls(false), sni_hostname(""), small_packet_count(0),
      medium_packet_count(0), large_packet_count(0) {}

void DnsAbuseFlowTracker::addPacket(const uint8_t *payload, size_t length,
                                    long timestamp_ms, bool is_forward) {
  if (start_time_ms == 0) {
    start_time_ms = timestamp_ms;
  }

  if (last_packet_time_ms > 0) {
    long iat = timestamp_ms - last_packet_time_ms;
    if (iat > 0) {
      flow_iat_stats.addValue(iat);
    }
  }

  last_packet_time_ms = timestamp_ms;
  flow_duration_ms = timestamp_ms - start_time_ms;

  flow_length_stats.addValue(length);

  // Exact port of Java's Encrypted DNS packet categorization
  if (length < 400) {
    small_packet_count++;
  } else if (length <= 600) {
    medium_packet_count++;
  } else {
    large_packet_count++;
  }

  if (is_forward) {
    fwd_count++;
    fwd_payload_stats.addValue(length);
    if (last_fwd_time_ms > 0) {
      long iat = timestamp_ms - last_fwd_time_ms;
      if (iat > 0)
        fwd_iat_stats.addValue(iat);
    }
    last_fwd_time_ms = timestamp_ms;
  } else {
    bwd_count++;
    bwd_payload_stats.addValue(length);
    if (last_bwd_time_ms > 0) {
      long iat = timestamp_ms - last_bwd_time_ms;
      if (iat > 0)
        bwd_iat_stats.addValue(iat);
    }
    last_bwd_time_ms = timestamp_ms;
  }

  if (src_port == 53 || dst_port == 53) {
    processDnsPacket(payload, length, timestamp_ms);
  } else if (src_port == 443 || dst_port == 443) {
    processTlsPacket(payload, length);
  }
}

void DnsAbuseFlowTracker::processDnsPacket(const uint8_t *payload,
                                           size_t length, long timestamp_ms) {
  // Very lightweight DNS binary parsing for speed
  // DNS Header is 12 bytes. payload[0-1]=Transaction ID, payload[2]=Flags
  if (length < 12)
    return;

  is_dns = true;

  uint16_t tx_id = (payload[0] << 8) | payload[1];
  uint8_t flags_qr = payload[2] & 0x80; // Is Response if high bit is set

  uint16_t qdcount = (payload[4] << 8) | payload[5];
  uint16_t ancount = (payload[6] << 8) | payload[7];

  total_question_count += qdcount;
  total_answer_count += ancount;

  if (flags_qr) {
    // Is Response
    dns_response_packet_count++;
    total_response_bytes += length;

    auto it = pending_queries.find(tx_id);
    if (it != pending_queries.end()) {
      double diff = timestamp_ms - it->second;
      response_time_sum += diff;
      response_time_sq_sum += (diff * diff);
      response_time_count++;
      pending_queries.erase(it);
    }
  } else {
    // Is Query
    dns_query_packet_count++;
    total_query_bytes += length;
    pending_queries[tx_id] = timestamp_ms;

    // Cleanup leak mechanism exactly as Java
    if (pending_queries.size() > 10000) {
      for (auto it = pending_queries.begin(); it != pending_queries.end();) {
        if ((timestamp_ms - it->second) > 5000) {
          it = pending_queries.erase(it);
        } else {
          ++it;
        }
      }
    }

    // Extract QType for every question (matching Java's looping behavior)
    size_t p = 12;
    for (int i = 0; i < qdcount; i++) {
      // Jump over QNAME labels
      while (p < length && payload[p] != 0x00) {
        if ((payload[p] & 0xC0) == 0xC0) {
          // Compressed pointer (2 bytes)
          p += 2;
          break;
        } else {
          p += payload[p] + 1; // Jump length of label + 1
        }
      }
      if (p < length && payload[p] == 0x00) {
        p++; // Jump the null terminator
      }

      // Extract QTYPE (2 bytes)
      if (p + 4 <= length) {
        uint16_t qtype = (payload[p] << 8) | payload[p + 1];
        if (qtype == 255)
          dns_any_count++;
        if (qtype == 16)
          dns_txt_count++;
        // Jump over QTYPE(2) and QCLASS(2) to next question
        p += 4;
      } else {
        break; // Malformed packet
      }
    }
  }
}

void DnsAbuseFlowTracker::processTlsPacket(const uint8_t *payload,
                                           size_t length) {
  if (length < 6)
    return;

  uint8_t content_type = payload[0];

  // TLS Handshake
  if (content_type == 0x16) {
    has_tls = true;
    if (length > 9 && payload[5] == 0x01) { // Client Hello
      sni_hostname = extractSni(payload, length);
    }
  }
  // TLS App Data (Encrypted payload)
  else if (content_type == 0x17 && length >= 5) {
    int recordLength = (payload[3] << 8) | payload[4];
    tls_payload_stats.addValue(recordLength);
  }
}

std::string DnsAbuseFlowTracker::extractSni(const uint8_t *payload,
                                            size_t length) {
  // Ported extractSni method from Java
  size_t p = 5;
  if (p + 4 > length)
    return "";
  int handshakeType = payload[p] & 0xFF;
  if (handshakeType != 1)
    return "";
  p += 4;

  if (p + 34 > length)
    return "";
  p += 34;

  if (p + 1 > length)
    return "";
  int sessionIdLen = payload[p] & 0xFF;
  p += 1;
  if (p + sessionIdLen > length)
    return "";
  p += sessionIdLen;

  if (p + 2 > length)
    return "";
  int cipherSuitesLen = (payload[p] << 8) | payload[p + 1];
  p += 2;
  if (p + cipherSuitesLen > length)
    return "";
  p += cipherSuitesLen;

  if (p + 1 > length)
    return "";
  int compMethodsLen = payload[p] & 0xFF;
  p += 1;
  if (p + compMethodsLen > length)
    return "";
  p += compMethodsLen;

  if (p + 2 > length)
    return "";
  int extensionsLen = (payload[p] << 8) | payload[p + 1];
  p += 2;

  size_t endOfExtensions = p + extensionsLen;
  if (endOfExtensions > length)
    endOfExtensions = length;

  while (p + 4 <= endOfExtensions) {
    int extType = (payload[p] << 8) | payload[p + 1];
    int extLen = (payload[p + 2] << 8) | payload[p + 3];
    p += 4;

    if (extType == 0) { // SNI
      if (p + 2 > endOfExtensions)
        return "";
      p += 2; // list len
      if (p + 1 > endOfExtensions)
        return "";
      int nameType = payload[p] & 0xFF; // 0 = host_name
      p += 1;

      if (nameType == 0) {
        if (p + 2 > endOfExtensions)
          return "";
        int nameLen = (payload[p] << 8) | payload[p + 1];
        p += 2;
        if (p + nameLen <= endOfExtensions) {
          return std::string(reinterpret_cast<const char *>(payload + p),
                             nameLen);
        }
      }
    } else {
      p += extLen;
    }
  }
  return "";
}

long DnsAbuseFlowTracker::getLastPacketTimeMs() { return last_packet_time_ms; }

double DnsAbuseFlowTracker::getFlowDurationSec() {
  double sec = flow_duration_ms / 1000.0;
  return sec <= 0 ? 1.0 : sec;
}

// ====================== 44 Features Ported ======================

// --- Category 1: DNS Critical
double DnsAbuseFlowTracker::getDnsAmplificationFactor() {
  if (!is_dns)
    return 0.0;
  if (total_query_bytes == 0)
    return total_response_bytes > 0 ? 999.0 : 0.0;
  if (total_response_bytes == 0)
    return 0.0;
  return (double)total_response_bytes / total_query_bytes;
}

double DnsAbuseFlowTracker::getQueryResponseRatio() {
  if (!is_dns)
    return 0.0;
  if (dns_response_packet_count == 0)
    return dns_query_packet_count;
  return (double)dns_query_packet_count / dns_response_packet_count;
}

double DnsAbuseFlowTracker::getDnsAnyQueryRatio() {
  if (!is_dns || dns_query_packet_count == 0)
    return 0.0;
  return (double)dns_any_count / dns_query_packet_count;
}

double DnsAbuseFlowTracker::getDnsTxtQueryRatio() {
  if (!is_dns || dns_query_packet_count == 0)
    return 0.0;
  return (double)dns_txt_count / dns_query_packet_count;
}

long DnsAbuseFlowTracker::getDnsResponseInconsistency() {
  if (!is_dns)
    return 0;
  return std::abs(dns_query_packet_count - dns_response_packet_count);
}

double DnsAbuseFlowTracker::getQueriesPerSecond() {
  if (!is_dns)
    return 0.0;
  return dns_query_packet_count / getFlowDurationSec();
}

double DnsAbuseFlowTracker::getPort53TrafficRatio() {
  if (!is_dns)
    return 0.0;
  long total_flow = flow_length_stats.getSum();
  if (total_flow == 0)
    return 0.0;
  long dns_traffic = total_query_bytes + total_response_bytes;
  return (double)dns_traffic / total_flow;
}

// --- Category 2: Flow Rates
double DnsAbuseFlowTracker::getFlowBytesPerSec() {
  return flow_length_stats.getSum() / getFlowDurationSec();
}
double DnsAbuseFlowTracker::getFlowPacketsPerSec() {
  return (fwd_count + bwd_count) / getFlowDurationSec();
}
double DnsAbuseFlowTracker::getFwdPacketsPerSec() {
  return fwd_count / getFlowDurationSec();
}
double DnsAbuseFlowTracker::getBwdPacketsPerSec() {
  return bwd_count / getFlowDurationSec();
}

// --- Category 3: Flow Statistics
long DnsAbuseFlowTracker::getTotalFwdPackets() { return fwd_count; }
long DnsAbuseFlowTracker::getTotalBwdPackets() { return bwd_count; }
double DnsAbuseFlowTracker::getTotalFwdBytes() {
  return fwd_payload_stats.getSum();
}
double DnsAbuseFlowTracker::getTotalBwdBytes() {
  return bwd_payload_stats.getSum();
}

// --- Category 4: DNS Aggregates
long DnsAbuseFlowTracker::getDnsTotalQueries() {
  return is_dns ? dns_query_packet_count : 0;
}
long DnsAbuseFlowTracker::getDnsTotalResponses() {
  return is_dns ? dns_response_packet_count : 0;
}
long DnsAbuseFlowTracker::getDnsResponseSize() {
  return is_dns ? total_response_bytes : 0;
}

// --- Category 5: Timing
double DnsAbuseFlowTracker::getFlowIatMean() {
  return flow_iat_stats.getMean();
}
double DnsAbuseFlowTracker::getFlowIatStd() {
  return flow_iat_stats.getStdDev();
}
double DnsAbuseFlowTracker::getFlowIatMin() { return flow_iat_stats.getMin(); }
double DnsAbuseFlowTracker::getFlowIatMax() { return flow_iat_stats.getMax(); }
double DnsAbuseFlowTracker::getFwdIatMean() { return fwd_iat_stats.getMean(); }
double DnsAbuseFlowTracker::getBwdIatMean() { return bwd_iat_stats.getMean(); }

// --- Category 6: Packet Sizes
double DnsAbuseFlowTracker::getFwdPacketLengthMean() {
  return fwd_payload_stats.getMean();
}
double DnsAbuseFlowTracker::getBwdPacketLengthMean() {
  return bwd_payload_stats.getMean();
}
double DnsAbuseFlowTracker::getPacketSizeStd() {
  return flow_length_stats.getStdDev();
}
double DnsAbuseFlowTracker::getFlowLengthMin() {
  return flow_length_stats.getMin();
}
double DnsAbuseFlowTracker::getFlowLengthMax() {
  return flow_length_stats.getMax();
}

// --- Category 7: Advanced
double DnsAbuseFlowTracker::getResponseTimeVariance() {
  if (!is_dns || response_time_count <= 1)
    return 0.0;
  double mean = response_time_sum / response_time_count;
  double var = (response_time_sq_sum / response_time_count) - (mean * mean);
  return var > 0 ? var : 0.0;
}
double DnsAbuseFlowTracker::getAveragePacketSize() {
  return flow_length_stats.getMean();
}

// --- Category 8: Encrypted DNS (DoH)
double DnsAbuseFlowTracker::getLargePacketRatio() {
  long total = fwd_count + bwd_count;
  return total > 0 ? (double)large_packet_count / total : 0.0;
}
double DnsAbuseFlowTracker::getMediumPacketRatio() {
  long total = fwd_count + bwd_count;
  return total > 0 ? (double)medium_packet_count / total : 0.0;
}
double DnsAbuseFlowTracker::getSmallPacketRatio() {
  long total = fwd_count + bwd_count;
  return total > 0 ? (double)small_packet_count / total : 0.0;
}

double DnsAbuseFlowTracker::calculateShannonEntropy(const std::string &str) {
  if (str.empty())
    return 0.0;
  std::map<char, int> freq;
  for (char c : str)
    freq[std::tolower(c)]++;
  double t = str.length();
  double ent = 0.0;
  for (auto const &pair : freq) {
    double p = pair.second / t;
    ent -= p * (std::log(p) / std::log(2));
  }
  return ent;
}

double DnsAbuseFlowTracker::getSniEntropy() {
  return calculateShannonEntropy(sni_hostname);
}
int DnsAbuseFlowTracker::isKnownDoHServer() {
  return DoHServerDatabase::isKnownServer(sni_hostname, dst_ip) ? 1 : 0;
}
double DnsAbuseFlowTracker::getEncryptedPayloadSizeVariance() {
  return tls_payload_stats.getVariance();
}
