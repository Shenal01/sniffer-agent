#include "DnsAbuseFlowManager.h"
#include <fmt/core.h>
#include <iostream>

DnsAbuseFlowManager::DnsAbuseFlowManager(ExportCallback cb)
    : export_callback(std::move(cb)) {}

void DnsAbuseFlowManager::processPacket(
    const uint8_t *payload, size_t length, long timestamp_ms,
    const std::string &src_ip, const std::string &dst_ip, int src_port,
    int dst_port, const std::string &protocol, bool is_tcp, uint8_t tcp_flags) {

  std::lock_guard<std::mutex> lock(manager_mutex);

  // Define bidirectional Flow Keys
  DnsAbuseFlowKey fwd_key(src_ip, dst_ip, src_port, dst_port, protocol);
  DnsAbuseFlowKey bwd_key(dst_ip, src_ip, dst_port, src_port, protocol);

  DnsAbuseFlowTracker *flow = nullptr;
  bool is_forward = true;

  // Check if flow already exists in either direction
  auto it_fwd = active_flows.find(fwd_key);
  auto it_bwd = active_flows.find(bwd_key);

  if (it_fwd != active_flows.end()) {
    flow = &it_fwd->second;
    is_forward = true;
  } else if (it_bwd != active_flows.end()) {
    flow = &it_bwd->second;
    is_forward = false;
  }

  // Strict timeout check BEFORE adding the packet to an existing flow
  if (flow != nullptr) {
    long last_time = flow->getLastPacketTimeMs(); // Assuming this is defined
    if ((timestamp_ms - last_time) > flow_timeout_ms) {
      // Flow timed out. Export it and treat this packet as start of NEW flow.
      exportFlow(*flow);

      if (is_forward) {
        active_flows.erase(it_fwd);
      } else {
        active_flows.erase(it_bwd);
      }
      flow = nullptr; // Force creation of new flow below
    }
  }

  if (flow == nullptr) {
    // New Flow - the side creating the flow is strictly standard Forward,
    // exactly like Java ML logic
    auto result = active_flows.emplace(
        std::piecewise_construct, std::forward_as_tuple(fwd_key),
        std::forward_as_tuple(src_ip, dst_ip, src_port, dst_port, protocol));
    flow = &result.first->second;
    is_forward = true;
  }

  // Process the packet statistics and specific DPI
  flow->addPacket(payload, length, timestamp_ms, is_forward);

  // FIX: TCP termination logic. If connection closes, instantly export to free
  // RAM and achieve true real-time metric updates in the database.
  if (is_tcp && (tcp_flags & 0x01 || tcp_flags & 0x04)) { // FIN or RST flag
    exportFlow(*flow);
    active_flows.erase(is_forward ? fwd_key : bwd_key);
    // Cannot proceed checking this packet inside manager, it is deleted
    return;
  }

  packet_counter++;

  // Lazy Cleanup: Check timeout every 5000 packets OR every 30 seconds
  if (packet_counter % 5000 == 0 ||
      (timestamp_ms - last_timeout_check_ms) > 30000) {
    checkTimeouts(timestamp_ms);
    last_timeout_check_ms = timestamp_ms;
  }

  // Performance monitoring: log every 10,000 packets
  if (packet_counter % 10000 == 0 && packet_counter > 0) {
    fmt::print("[DnsAbuse] Processed {} packets, {} active flows\n",
               packet_counter, active_flows.size());
  }
}

void DnsAbuseFlowManager::checkTimeouts(long current_time_ms) {
  std::vector<DnsAbuseFlowKey> to_remove;

  for (auto &entry : active_flows) {
    if ((current_time_ms - entry.second.getLastPacketTimeMs()) >
        flow_timeout_ms) {
      exportFlow(entry.second);
      to_remove.push_back(entry.first);
    }
  }

  for (const auto &key : to_remove) {
    active_flows.erase(key);
  }
}

void DnsAbuseFlowManager::dumpAll() {
  std::lock_guard<std::mutex> lock(manager_mutex);
  for (auto &entry : active_flows) {
    exportFlow(entry.second);
  }
  active_flows.clear();
}

void DnsAbuseFlowManager::exportFlow(DnsAbuseFlowTracker &flow) {
  if (export_callback) {
    export_callback(flow);
  }
}
