#pragma once

#include "flows/dns_abuse/DnsAbuseFlowManager.h"
#include "flows/flow_tracker.h"
#include "parsers/dns_parser.h"
#include "storage/db_writer.h"
#include <pcap.h>


namespace capture {

class PacketDispatcher {
public:
  PacketDispatcher(storage::DbWriter &db_writer);

  void handle_packet(const struct pcap_pkthdr *header, const uint8_t *packet);
  void cleanup_flows();

private:
  storage::DbWriter &db_writer_;
  parsers::DnsParser dns_parser_;
  flows::FlowTracker flow_tracker_;
  DnsAbuseFlowManager dns_abuse_manager_;
};

} // namespace capture
