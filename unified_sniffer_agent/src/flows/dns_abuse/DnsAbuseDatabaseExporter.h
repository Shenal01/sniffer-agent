#ifndef DNS_ABUSE_DATABASE_EXPORTER_H
#define DNS_ABUSE_DATABASE_EXPORTER_H

#include "DnsAbuseFlowTracker.h"
#include <string>

/**
 * Handles generating exact MySQL query strings for the 44 DNS abuse features.
 * Guarantees that all columns are namespaced with `features.dns_abuse.`
 * to prevent collisions with the DGA and Tunneling teams.
 */
class DnsAbuseDatabaseExporter {
public:
  // Takes the finished 5-tuple flow and generates an INSERT statement
  static std::string generateSqlStatement(DnsAbuseFlowTracker &flow);
};

#endif // DNS_ABUSE_DATABASE_EXPORTER_H
