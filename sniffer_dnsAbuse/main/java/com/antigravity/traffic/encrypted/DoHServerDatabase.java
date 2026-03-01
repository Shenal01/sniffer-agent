package com.antigravity.traffic.encrypted;

import java.util.HashSet;
import java.util.Set;

/**
 * Database of known public DoH servers for identification.
 * Sources:
 * - https://github.com/curl/curl/wiki/DNS-over-HTTPS
 * - Public DNS providers list
 */
public class DoHServerDatabase {

    private static final Set<String> KNOWN_HOSTNAMES = new HashSet<>();
    private static final Set<String> KNOWN_IPS = new HashSet<>();

    static {
        // --- HIGH TRUST: Global Public Resolvers ---

        // Google Public DNS
        KNOWN_HOSTNAMES.add("dns.google");
        KNOWN_HOSTNAMES.add("dns.google.com");
        KNOWN_IPS.add("8.8.8.8");
        KNOWN_IPS.add("8.8.4.4");
        KNOWN_IPS.add("2001:4860:4860::8888");
        KNOWN_IPS.add("2001:4860:4860::8844");

        // Cloudflare (1.1.1.1, Security, Family)
        KNOWN_HOSTNAMES.add("cloudflare-dns.com");
        KNOWN_HOSTNAMES.add("security.cloudflare-dns.com");
        KNOWN_HOSTNAMES.add("family.cloudflare-dns.com");
        KNOWN_HOSTNAMES.add("one.one.one.one");
        KNOWN_IPS.add("1.1.1.1");
        KNOWN_IPS.add("1.0.0.1");
        KNOWN_IPS.add("1.1.1.2");
        KNOWN_IPS.add("1.0.0.2");
        KNOWN_IPS.add("1.1.1.3");
        KNOWN_IPS.add("1.0.0.3");
        KNOWN_IPS.add("2606:4700:4700::1111");
        KNOWN_IPS.add("2606:4700:4700::1001");

        // Quad9 (Standard + Unfiltered)
        KNOWN_HOSTNAMES.add("dns.quad9.net");
        KNOWN_HOSTNAMES.add("dns-nosec.quad9.net");
        KNOWN_IPS.add("9.9.9.9");
        KNOWN_IPS.add("149.112.112.112");
        KNOWN_IPS.add("9.9.9.10");
        KNOWN_IPS.add("149.112.112.10");
        KNOWN_IPS.add("2620:fe::fe");

        // OpenDNS (Cisco)
        KNOWN_HOSTNAMES.add("doh.opendns.com");
        KNOWN_HOSTNAMES.add("doh.familyshield.opendns.com");
        KNOWN_HOSTNAMES.add("resolver1.opendns.com");
        KNOWN_HOSTNAMES.add("resolver2.opendns.com");
        KNOWN_IPS.add("208.67.222.222");
        KNOWN_IPS.add("208.67.220.220");

        // Verisign
        KNOWN_HOSTNAMES.add("doh.verisign.com");
        KNOWN_IPS.add("64.6.64.6");
        KNOWN_IPS.add("64.6.65.6");

        // AdGuard
        KNOWN_HOSTNAMES.add("dns.adguard.com");
        KNOWN_HOSTNAMES.add("dns-family.adguard.com");
        KNOWN_IPS.add("94.140.14.14");
        KNOWN_IPS.add("94.140.15.15");

        // Mullvad
        KNOWN_HOSTNAMES.add("doh.mullvad.net");
        KNOWN_IPS.add("194.242.2.2");

        // DNS.SB
        KNOWN_HOSTNAMES.add("dot.sb");
        KNOWN_IPS.add("185.222.222.222");
        KNOWN_IPS.add("45.11.45.11");

        // G-Core
        KNOWN_IPS.add("95.85.95.85");
        KNOWN_IPS.add("2.56.220.2");

        // --- HIGH TRUST: Govt/ISP/Regional ---

        // NTT / GIN (Tier-1)
        KNOWN_HOSTNAMES.add("x.ns.gin.ntt.net");
        KNOWN_HOSTNAMES.add("y.ns.gin.ntt.net");
        KNOWN_IPS.add("129.250.35.250");
        KNOWN_IPS.add("129.250.35.251");

        // TWNIC Quad101 (Taiwan)
        KNOWN_HOSTNAMES.add("twnic-public-dns.twnic.tw");
        KNOWN_IPS.add("101.101.101.101");
        KNOWN_IPS.add("101.102.103.104");

        // CIRA Canadian Shield
        KNOWN_IPS.add("149.112.121.10");
        KNOWN_IPS.add("149.112.122.10");

        // DNS4EU
        KNOWN_IPS.add("86.54.11.100");
        KNOWN_IPS.add("86.54.11.1");

        // Hurricane Electric (Anycast)
        KNOWN_HOSTNAMES.add("ordns.he.net");
        KNOWN_IPS.add("74.82.42.42");

        // --- MEDIUM TRUST: Major Providers & ISPs ---

        // Yandex.DNS (Russia - SORM risks, but valid DoH)
        KNOWN_HOSTNAMES.add("dns.yandex.ru");
        KNOWN_IPS.add("77.88.8.8");
        KNOWN_IPS.add("77.88.8.1");

        // Comcast
        KNOWN_IPS.add("75.75.75.75");
        KNOWN_IPS.add("75.75.76.76");

        // AT&T
        KNOWN_IPS.add("68.94.156.1");

        // Level3 / Lumen
        KNOWN_HOSTNAMES.add("resolver1.level3.net");
        KNOWN_IPS.add("4.2.2.1");
        KNOWN_IPS.add("4.2.2.2");
        KNOWN_IPS.add("209.244.0.3");

        // AliDNS (China)
        KNOWN_HOSTNAMES.add("dns.alidns.com");
        KNOWN_IPS.add("223.5.5.5");
        KNOWN_IPS.add("223.6.6.6");

        // DNSPod (Tencent)
        KNOWN_HOSTNAMES.add("doh.pub");
        KNOWN_IPS.add("1.12.12.12");
        KNOWN_IPS.add("120.53.53.53");
    }

    /**
     * Check if hostname or IP is a known public DoH server.
     * 
     * @param hostname SNI hostname (can be null)
     * @param ip       Destination IP address (can be null)
     * @return true if matches known DoH server
     */
    public static boolean isKnownDoHServer(String hostname, String ip) {
        if (hostname != null && !hostname.isEmpty()) {
            if (KNOWN_HOSTNAMES.contains(hostname.toLowerCase())) {
                return true;
            }
        }

        if (ip != null && !ip.isEmpty()) {
            if (KNOWN_IPS.contains(ip)) {
                return true;
            }
        }

        return false;
    }
}
