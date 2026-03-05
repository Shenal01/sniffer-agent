#ifndef DNS_ABUSE_FLOW_KEY_H
#define DNS_ABUSE_FLOW_KEY_H

#include <string>
#include <tuple>

/**
 * Port of FlowKey.java
 * Strict 5-Tuple flow tracking to guarantee 100% accurate separation of flows,
 * replacing the flawed native flow key which ignores protocol.
 */
class DnsAbuseFlowKey {
public:
  std::string src_ip;
  std::string dst_ip;
  int src_port;
  int dst_port;
  std::string protocol;

  DnsAbuseFlowKey(std::string src, std::string dst, int sport, int dport,
                  std::string proto)
      : src_ip(std::move(src)), dst_ip(std::move(dst)), src_port(sport),
        dst_port(dport), protocol(std::move(proto)) {}

  // Necessary for using this class as a key in std::map
  bool operator<(const DnsAbuseFlowKey &other) const {
    return std::tie(src_ip, dst_ip, src_port, dst_port, protocol) <
           std::tie(other.src_ip, other.dst_ip, other.src_port, other.dst_port,
                    other.protocol);
  }

  bool operator==(const DnsAbuseFlowKey &other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port &&
           protocol == other.protocol;
  }
};

#endif // DNS_ABUSE_FLOW_KEY_H
