#ifndef DNS_ABUSE_FLOW_MANAGER_H
#define DNS_ABUSE_FLOW_MANAGER_H

#include "DnsAbuseFlowKey.h"
#include "DnsAbuseFlowTracker.h"
#include <functional>
#include <map>
#include <mutex>
#include <vector>


/**
 * Port of FlowManager.java
 * Replicates the exact Java lifecycle for grouping packets into flows
 * and handling timeouts (120,000ms), ignoring the flawed native flow tracking.
 */
class DnsAbuseFlowManager {
public:
  // Callback executed when a flow completes (timeout or forced dump).
  // This is where we'll hook into MySQL inserts.
  using ExportCallback = std::function<void(DnsAbuseFlowTracker &)>;

private:
  std::map<DnsAbuseFlowKey, DnsAbuseFlowTracker> active_flows;
  std::mutex manager_mutex;
  ExportCallback export_callback;

  const long flow_timeout_ms = 120000; // 2 minutes, exactly matching Java
  long packet_counter = 0;
  long last_timeout_check_ms = 0;

  void exportFlow(DnsAbuseFlowTracker &flow);

public:
  explicit DnsAbuseFlowManager(ExportCallback cb);

  // Equivalent to Java's FlowManager.processPacket()
  void processPacket(const uint8_t *payload, size_t length, long timestamp_ms,
                     const std::string &src_ip, const std::string &dst_ip,
                     int src_port, int dst_port, const std::string &protocol,
                     bool is_tcp, uint8_t tcp_flags);

  // Check for flows that exceed the 120s timeout and export them
  void checkTimeouts(long current_time_ms);

  // Export and clear all remaining flows (on shutdown)
  void dumpAll();
};

#endif // DNS_ABUSE_FLOW_MANAGER_H
