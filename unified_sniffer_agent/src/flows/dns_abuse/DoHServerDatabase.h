#ifndef DOH_SERVER_DATABASE_H
#define DOH_SERVER_DATABASE_H

#include <algorithm>
#include <string>
#include <unordered_set>


/**
 * Database of known public DoH servers for identification.
 * Ported EXACTLY from DoHServerDatabase.java
 */
class DoHServerDatabase {
private:
  static const std::unordered_set<std::string> &getKnownHostnames() {
    static const std::unordered_set<std::string> hostnames = {
        "dns.google",
        "dns.google.com",
        "cloudflare-dns.com",
        "security.cloudflare-dns.com",
        "family.cloudflare-dns.com",
        "one.one.one.one",
        "dns.quad9.net",
        "dns-nosec.quad9.net",
        "doh.opendns.com",
        "doh.familyshield.opendns.com",
        "resolver1.opendns.com",
        "resolver2.opendns.com",
        "doh.verisign.com",
        "dns.adguard.com",
        "dns-family.adguard.com",
        "doh.mullvad.net",
        "dot.sb",
        "x.ns.gin.ntt.net",
        "y.ns.gin.ntt.net",
        "twnic-public-dns.twnic.tw",
        "ordns.he.net",
        "dns.yandex.ru",
        "resolver1.level3.net",
        "dns.alidns.com",
        "doh.pub"};
    return hostnames;
  }

  static const std::unordered_set<std::string> &getKnownIps() {
    static const std::unordered_set<std::string> ips = {"8.8.8.8",
                                                        "8.8.4.4",
                                                        "2001:4860:4860::8888",
                                                        "2001:4860:4860::8844",
                                                        "1.1.1.1",
                                                        "1.0.0.1",
                                                        "1.1.1.2",
                                                        "1.0.0.2",
                                                        "1.1.1.3",
                                                        "1.0.0.3",
                                                        "2606:4700:4700::1111",
                                                        "2606:4700:4700::1001",
                                                        "9.9.9.9",
                                                        "149.112.112.112",
                                                        "9.9.9.10",
                                                        "149.112.112.10",
                                                        "2620:fe::fe",
                                                        "208.67.222.222",
                                                        "208.67.220.220",
                                                        "64.6.64.6",
                                                        "64.6.65.6",
                                                        "94.140.14.14",
                                                        "94.140.15.15",
                                                        "194.242.2.2",
                                                        "185.222.222.222",
                                                        "45.11.45.11",
                                                        "95.85.95.85",
                                                        "2.56.220.2",
                                                        "129.250.35.250",
                                                        "129.250.35.251",
                                                        "101.101.101.101",
                                                        "101.102.103.104",
                                                        "149.112.121.10",
                                                        "149.112.122.10",
                                                        "86.54.11.100",
                                                        "86.54.11.1",
                                                        "74.82.42.42",
                                                        "77.88.8.8",
                                                        "77.88.8.1",
                                                        "75.75.75.75",
                                                        "75.75.76.76",
                                                        "68.94.156.1",
                                                        "4.2.2.1",
                                                        "4.2.2.2",
                                                        "209.244.0.3",
                                                        "223.5.5.5",
                                                        "223.6.6.6",
                                                        "1.12.12.12",
                                                        "120.53.53.53"};
    return ips;
  }

  static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
  }

public:
  static bool isKnownServer(const std::string &hostname,
                            const std::string &ip) {
    if (!hostname.empty()) {
      if (getKnownHostnames().count(toLower(hostname))) {
        return true;
      }
    }
    if (!ip.empty()) {
      if (getKnownIps().count(ip)) {
        return true;
      }
    }
    return false;
  }

  // Simplified DNS Protocol detection ported from DnsProtocol.java
  static std::string detectProtocol(int srcPort, int dstPort, bool hasTls,
                                    const std::string &sni,
                                    const std::string &ip) {
    if (srcPort == 53 || dstPort == 53) {
      return "TRADITIONAL";
    }
    if (srcPort == 853 || dstPort == 853) {
      return "DOT";
    }
    if (srcPort == 443 || dstPort == 443) {
      if (isKnownServer(sni, ip)) {
        return "DOH";
      }
    }
    if (hasTls) {
      return "TLS";
    }
    return "UNKNOWN";
  }
};

#endif // DOH_SERVER_DATABASE_H
