package com.antigravity.traffic;

import java.net.InetAddress;
import java.util.Objects;

/**
 * Represents the 5-tuple key for a flow:
 * Source IP, Destination IP, Source Port, Destination Port, Protocol.
 * 
 * Note: For bidirectional flow matching, we need a canonical representation
 * or the FlowManager needs to handle lookup for both directions.
 * Usually, CIC flows are determined by the first packet.
 */
public class FlowKey {
    private final InetAddress srcIp;
    private final InetAddress dstIp;
    private final int srcPort;
    private final int dstPort;
    private final String protocol;

    public FlowKey(InetAddress srcIp, InetAddress dstIp, int srcPort, int dstPort, String protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public InetAddress getSrcIp() { return srcIp; }
    public InetAddress getDstIp() { return dstIp; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public String getProtocol() { return protocol; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlowKey flowKey = (FlowKey) o;
        return srcPort == flowKey.srcPort &&
                dstPort == flowKey.dstPort &&
                srcIp.equals(flowKey.srcIp) &&
                dstIp.equals(flowKey.dstIp) &&
                protocol.equals(flowKey.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort + " [" + protocol + "]";
    }
}
