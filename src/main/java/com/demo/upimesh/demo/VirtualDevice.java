package com.demo.upimesh.demo;

import com.demo.upimesh.protocol.MeshPacket;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** A simulated phone in the mesh: just the packets it is carrying. */
public class VirtualDevice {

    private final String deviceId;
    private final boolean hasInternet;
    private final Map<String, MeshPacket> held = new ConcurrentHashMap<>();

    public VirtualDevice(String deviceId, boolean hasInternet) {
        this.deviceId = deviceId;
        this.hasInternet = hasInternet;
    }

    public String getDeviceId() { return deviceId; }
    public boolean hasInternet() { return hasInternet; }
    public void hold(MeshPacket p) { held.putIfAbsent(p.packetId(), p); }
    public boolean holds(String packetId) { return held.containsKey(packetId); }
    public Collection<MeshPacket> getHeldPackets() { return held.values(); }
    public int packetCount() { return held.size(); }
    public void drop(String packetId) { held.remove(packetId); }
    public void clear() { held.clear(); }
}
