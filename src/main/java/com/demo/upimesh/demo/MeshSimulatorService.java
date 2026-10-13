package com.demo.upimesh.demo;

import com.demo.upimesh.protocol.MeshPacket;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal mesh: every device gossips with every other device each round.
 * (Phase 2 replaces this with pairwise random gossip between moving nodes,
 * spray-and-wait, buffer caps and receipt-driven purging.)
 */
@Service
@Profile("demo")
public class MeshSimulatorService {

    public record GossipResult(int transfers, Map<String, Integer> deviceCounts) {}
    public record BridgeUpload(String bridgeNodeId, MeshPacket packet) {}

    private final Map<String, VirtualDevice> devices = new ConcurrentHashMap<>();

    public MeshSimulatorService() {
        for (String id : List.of("phone-alice", "phone-stranger1", "phone-stranger2", "phone-stranger3")) {
            devices.put(id, new VirtualDevice(id, false));
        }
        devices.put("phone-bridge", new VirtualDevice("phone-bridge", true));
    }

    public Collection<VirtualDevice> getDevices() { return devices.values(); }

    public void inject(String deviceId, MeshPacket packet) {
        VirtualDevice d = devices.get(deviceId);
        if (d == null) throw new IllegalArgumentException("Unknown device: " + deviceId);
        d.hold(packet);
    }

    public GossipResult gossipOnce() {
        int transfers = 0;
        List<VirtualDevice> list = new ArrayList<>(devices.values());
        Map<String, List<MeshPacket>> snapshot = new HashMap<>();
        for (VirtualDevice d : list) snapshot.put(d.getDeviceId(), new ArrayList<>(d.getHeldPackets()));
        for (VirtualDevice src : list) {
            for (MeshPacket p : snapshot.get(src.getDeviceId())) {
                if (p.ttl() <= 0) continue;
                for (VirtualDevice dst : list) {
                    if (dst == src || dst.holds(p.packetId())) continue;
                    dst.hold(p.hop());
                    transfers++;
                }
            }
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        devices.values().forEach(d -> counts.put(d.getDeviceId(), d.packetCount()));
        return new GossipResult(transfers, counts);
    }

    public List<BridgeUpload> collectBridgeUploads() {
        List<BridgeUpload> out = new ArrayList<>();
        for (VirtualDevice d : devices.values()) {
            if (!d.hasInternet()) continue;
            d.getHeldPackets().forEach(p -> out.add(new BridgeUpload(d.getDeviceId(), p)));
        }
        return out;
    }

    /** A receipt came back: every device drops the packet. */
    public void purge(String packetId) {
        devices.values().forEach(d -> d.drop(packetId));
    }

    public void reset() {
        devices.values().forEach(VirtualDevice::clear);
    }
}
