package com.demo.upimesh.demo.mesh;

import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.SettlementReceipt;

import java.util.LinkedHashMap;
import java.util.Map;

/** One simulated phone: where it is, how much battery it has, and what it is carrying. */
public class SimNode {

    /** A packet in a phone's buffer, with the spray-and-wait copy budget this phone holds for it. */
    public record Carried(MeshPacket packet, String hash, int copies, int hops, int receivedTick,
                          int createdTick, boolean ownPacket) {
        Carried withCopies(int c) { return new Carried(packet, hash, c, hops, receivedTick, createdTick, ownPacket); }
    }

    final String id;
    final String label;
    final String ownerVpa; // null for strangers
    double x, y, targetX, targetY, speed;
    double battery;
    boolean scanning;
    boolean radioOn = true;
    /** An attacker's phone: ignores receipts and keeps pushing whatever it carries. */
    boolean malicious;
    /** insertion-ordered so the oldest stranger packet is evicted first */
    final Map<String, Carried> buffer = new LinkedHashMap<>();
    /** packetHash -> receipt, bounded LRU */
    final Map<String, SettlementReceipt> receipts;

    SimNode(String id, String label, String ownerVpa, int receiptCapacity) {
        this.id = id;
        this.label = label;
        this.ownerVpa = ownerVpa;
        this.receipts = new LinkedHashMap<>(16, 0.75f, false) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, SettlementReceipt> e) {
                return size() > receiptCapacity;
            }
        };
    }

    public String id() { return id; }
    public String label() { return label; }
    public String ownerVpa() { return ownerVpa; }
    public double x() { return x; }
    public double y() { return y; }
    public double battery() { return battery; }
    public boolean scanning() { return scanning; }
    public boolean radioOn() { return radioOn; }
    public boolean malicious() { return malicious; }
    public void setMalicious(boolean m) { this.malicious = m; }
    public Map<String, Carried> buffer() { return buffer; }
    public Map<String, SettlementReceipt> receipts() { return receipts; }
}
