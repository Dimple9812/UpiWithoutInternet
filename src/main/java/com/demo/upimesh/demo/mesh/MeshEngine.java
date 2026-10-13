package com.demo.upimesh.demo.mesh;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.SettlementReceipt;
import com.demo.upimesh.service.IngestionService.IngestResult;
import com.demo.upimesh.demo.mesh.SimNode.Carried;

import java.util.*;

/**
 * Discrete-time simulation of phones moving around and relaying packets.
 * Plain Java (no Spring) so it can be unit tested deterministically with a seed.
 *
 * <h3>Per tick</h3>
 * <ol>
 *   <li><b>Move</b> — random-waypoint mobility.</li>
 *   <li><b>Battery</b> — idle drain, scan drain, charging inside 4G coverage. Below
 *       {@code lowBattery} a phone scans only every third tick; below {@code criticalBattery}
 *       its radio is off.</li>
 *   <li><b>Contacts</b> — every pair of scanning phones within {@code radioRange} exchanges
 *       data, pairwise.</li>
 *   <li><b>Exchange</b> — receipts first (they are small and kill packets), then packets by
 *       binary spray-and-wait: a holder with c&gt;1 copies hands floor(c/2) to a phone that
 *       lacks the packet; with c=1 it waits and only hands it to a phone that has 4G.</li>
 *   <li><b>Upload</b> — phones inside coverage upload what they carry; each signed receipt
 *       they get back is kept and gossiped, and every phone that sees it drops the packet.</li>
 *   <li><b>Expire</b> — packets older than {@code packetLifetime} are dropped.</li>
 * </ol>
 */
public class MeshEngine {

    /** How the engine reaches the backend (the demo wires this to IngestionService). */
    public interface Uploader {
        IngestResult upload(MeshPacket packet, String bridgeId, int hops);
    }

    public record Event(int tick, String kind, String text, String packetHash) {}

    public record Contact(String a, String b) {}

    public static final class Stats {
        public int created, transfers, receiptTransfers, uploads, settled, rejected, duplicates, retries,
                purgedByReceipt, expired, evicted, refused;
        public long latencyTicksSum, hopsSum;

        public double avgLatencyTicks() { return settled == 0 ? 0 : (double) latencyTicksSum / settled; }
        public double avgHops() { return settled == 0 ? 0 : (double) hopsSum / settled; }
        public double duplicateRate() { return uploads == 0 ? 0 : (double) duplicates / uploads; }
    }

    private final MeshConfig cfg;
    private final Random rnd;
    private final Uploader uploader;
    private final Map<String, SimNode> nodes = new LinkedHashMap<>();
    private final Deque<Event> events = new ArrayDeque<>();
    private final List<Contact> lastContacts = new ArrayList<>();
    private final Map<String, Integer> createdTickByHash = new HashMap<>();
    private Stats stats = new Stats();
    private int tick;

    public MeshEngine(MeshConfig cfg, long seed, Uploader uploader) {
        this.cfg = cfg;
        this.rnd = new Random(seed);
        this.uploader = uploader;
    }

    // ------------------------------------------------------------------ setup

    public SimNode addNode(String id, String label, String ownerVpa) {
        SimNode n = new SimNode(id, label, ownerVpa, cfg.receiptCapacity());
        n.x = rnd.nextDouble() * cfg.coverageX() * 0.9;
        n.y = rnd.nextDouble() * cfg.height();
        n.battery = 35 + rnd.nextDouble() * 65;
        pickTarget(n);
        nodes.put(id, n);
        return n;
    }

    public void place(String id, double x, double y, double battery) {
        SimNode n = node(id);
        n.x = x; n.y = y; n.battery = battery;
        n.targetX = x; n.targetY = y; n.speed = 0;
    }

    /** Send a phone walking towards a point (e.g. "walk outside to get 4G"). */
    public void walkTo(String id, double x, double y) {
        SimNode n = node(id);
        n.targetX = x; n.targetY = y;
        n.speed = cfg.maxSpeed();
    }

    /** Freeze a node in place (tests, or "stand still" in the UI). */
    public void pin(String id) {
        SimNode n = node(id);
        n.targetX = n.x; n.targetY = n.y; n.speed = 0;
    }

    public Carried inject(String nodeId, MeshPacket packet) {
        SimNode n = node(nodeId);
        String hash = hashOf(packet);
        Carried c = new Carried(packet, hash, cfg.initialCopies(), 0, tick, tick, true);
        n.buffer.put(packet.packetId(), c);
        createdTickByHash.putIfAbsent(hash, tick);
        stats.created++;
        log("send", n.label + " signed a payment and holds it (" + cfg.initialCopies() + " copies to spray)", hash);
        return c;
    }

    /** A relay's copy, e.g. a malicious relay re-injecting something it altered. */
    public void injectAsRelay(String nodeId, MeshPacket packet, int copies) {
        SimNode n = node(nodeId);
        String hash = hashOf(packet);
        n.buffer.put(packet.packetId(), new Carried(packet, hash, copies, 1, tick, tick, false));
        createdTickByHash.putIfAbsent(hash, tick);
    }

    public void reset(long seed) {
        rnd.setSeed(seed);
        tick = 0;
        stats = new Stats();
        events.clear();
        lastContacts.clear();
        createdTickByHash.clear();
        for (SimNode n : nodes.values()) {
            n.buffer.clear();
            n.receipts.clear();
            n.x = rnd.nextDouble() * cfg.coverageX() * 0.9;
            n.y = rnd.nextDouble() * cfg.height();
            n.battery = 35 + rnd.nextDouble() * 65;
            n.radioOn = true;
            pickTarget(n);
        }
    }

    // ------------------------------------------------------------------ tick

    public void step() {
        tick++;
        for (SimNode n : nodes.values()) move(n);
        for (SimNode n : nodes.values()) power(n);

        lastContacts.clear();
        List<SimNode> list = new ArrayList<>(nodes.values());
        for (int i = 0; i < list.size(); i++) {
            for (int j = i + 1; j < list.size(); j++) {
                SimNode a = list.get(i), b = list.get(j);
                if (a.scanning && b.scanning && dist(a, b) <= cfg.radioRange()) {
                    lastContacts.add(new Contact(a.id, b.id));
                }
            }
        }
        Collections.shuffle(lastContacts, rnd); // no phone is systematically first
        for (Contact c : lastContacts) exchange(node(c.a()), node(c.b()));

        for (SimNode n : nodes.values()) if (online(n) && n.radioOn) upload(n);
        for (SimNode n : nodes.values()) expire(n);
    }

    // ------------------------------------------------------------------ phases

    private void move(SimNode n) {
        if (n.speed == 0) return;
        double dx = n.targetX - n.x, dy = n.targetY - n.y;
        double d = Math.hypot(dx, dy);
        if (d <= n.speed) {
            n.x = n.targetX; n.y = n.targetY;
            pickTarget(n);
        } else {
            n.x += dx / d * n.speed;
            n.y += dy / d * n.speed;
        }
    }

    private void pickTarget(SimNode n) {
        n.targetX = rnd.nextDouble() * cfg.width();
        n.targetY = rnd.nextDouble() * cfg.height();
        n.speed = cfg.minSpeed() + rnd.nextDouble() * (cfg.maxSpeed() - cfg.minSpeed());
    }

    private void power(SimNode n) {
        n.battery -= cfg.idleDrain();
        if (online(n)) n.battery += cfg.chargeRate(); // charging point inside coverage
        n.battery = Math.max(0, Math.min(100, n.battery));

        boolean wasOn = n.radioOn;
        n.radioOn = n.battery > cfg.criticalBattery();
        if (wasOn && !n.radioOn) log("battery", n.label + " is almost flat: radio off, still carrying " + n.buffer.size(), null);
        if (!wasOn && n.radioOn) log("battery", n.label + " recharged: radio back on", null);

        // battery-aware scanning: low battery phones scan one tick in three
        n.scanning = n.radioOn && (n.battery > cfg.lowBattery() || tick % 3 == 0);
        if (n.scanning) n.battery = Math.max(0, n.battery - cfg.scanDrain());
    }

    private void exchange(SimNode a, SimNode b) {
        shareReceipts(a, b);
        shareReceipts(b, a);
        forward(a, b);
        forward(b, a);
    }

    private void shareReceipts(SimNode from, SimNode to) {
        for (Map.Entry<String, SettlementReceipt> e : List.copyOf(from.receipts.entrySet())) {
            if (to.malicious || to.receipts.containsKey(e.getKey())) continue;
            to.receipts.put(e.getKey(), e.getValue());
            stats.receiptTransfers++;
            if (to.ownerVpa != null && (to.ownerVpa.equals(e.getValue().receiverVpa())
                    || to.ownerVpa.equals(e.getValue().senderVpa()))) {
                log("receipt", to.label + " learned the payment is " + e.getValue().status().toLowerCase()
                        + " (receipt via " + from.label + ")", e.getKey());
            }
        }
        purge(to);
    }

    private void purge(SimNode n) {
        if (n.malicious) return;
        Iterator<Carried> it = n.buffer.values().iterator();
        while (it.hasNext()) {
            Carried c = it.next();
            if (n.receipts.containsKey(c.hash())) {
                it.remove();
                stats.purgedByReceipt++;
            }
        }
    }

    private void forward(SimNode from, SimNode to) {
        int moved = 0;
        for (Carried c : List.copyOf(from.buffer.values())) {
            if (moved >= cfg.maxPerContact()) break;
            if (to.buffer.containsKey(c.packet().packetId()) || to.receipts.containsKey(c.hash())) continue;
            if (c.packet().ttl() <= 0) continue; // hop limit reached
            int give;
            if (c.copies() > 1) {
                give = c.copies() / 2;                     // spray phase
            } else if (online(to)) {
                give = 1;                                  // wait phase: direct delivery to a bridge only
            } else {
                continue;
            }
            Carried copy = new Carried(c.packet().hop(), c.hash(), give, c.hops() + 1, tick, c.createdTick(), false);
            if (!accept(to, copy)) continue;
            if (c.copies() > 1) from.buffer.put(c.packet().packetId(), c.withCopies(c.copies() - give));
            stats.transfers++;
            moved++;
            log("relay", from.label + " → " + to.label + " (" + give + (give == 1 ? " copy" : " copies") + ")", c.hash());
        }
    }

    private boolean accept(SimNode n, Carried c) {
        if (n.buffer.size() >= cfg.bufferCapacity()) {
            Optional<String> victim = n.buffer.values().stream().filter(x -> !x.ownPacket())
                    .map(x -> x.packet().packetId()).findFirst(); // oldest stranger packet
            if (victim.isEmpty()) { stats.refused++; return false; }
            n.buffer.remove(victim.get());
            stats.evicted++;
        }
        n.buffer.put(c.packet().packetId(), c);
        return true;
    }

    private void upload(SimNode n) {
        for (Carried c : List.copyOf(n.buffer.values())) {
            IngestResult r;
            try {
                r = uploader.upload(c.packet(), n.id, c.hops());
            } catch (RuntimeException e) {
                stats.retries++;
                log("retry", n.label + " upload failed (" + e.getClass().getSimpleName() + "), will retry", c.hash());
                continue;
            }
            stats.uploads++;
            switch (r.outcome()) {
                case SETTLED -> {
                    stats.settled++;
                    stats.hopsSum += c.hops();
                    stats.latencyTicksSum += tick - createdTickByHash.getOrDefault(c.hash(), c.createdTick());
                    log("settled", n.label + " uploaded it: settled ₹" + r.receipt().amount()
                            + " after " + c.hops() + (c.hops() == 1 ? " hop" : " hops"), c.hash());
                }
                case REJECTED -> {
                    stats.rejected++;
                    log("rejected", n.label + " uploaded it: rejected (" + r.reason() + ")", c.hash());
                }
                case DUPLICATE -> stats.duplicates++;
                case RETRY -> {
                    stats.retries++;
                    log("retry", n.label + " got RETRY (" + r.reason() + "), keeping the packet", c.hash());
                    continue;
                }
            }
            if (r.receipt() != null && !n.malicious) n.receipts.put(c.hash(), r.receipt());
            n.buffer.remove(c.packet().packetId());
        }
        purge(n);
    }

    private void expire(SimNode n) {
        Iterator<Carried> it = n.buffer.values().iterator();
        while (it.hasNext()) {
            Carried c = it.next();
            if (tick - c.createdTick() > cfg.packetLifetime()) {
                it.remove();
                stats.expired++;
                if (c.ownPacket()) log("expired", n.label + "'s own packet expired before reaching the internet", c.hash());
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    public boolean online(SimNode n) { return n.x >= cfg.coverageX(); }

    private static double dist(SimNode a, SimNode b) { return Math.hypot(a.x - b.x, a.y - b.y); }

    public static String hashOf(MeshPacket p) { return Crypto.sha256Hex(Crypto.unb64(p.ciphertext())); }

    public SimNode node(String id) {
        SimNode n = nodes.get(id);
        if (n == null) throw new IllegalArgumentException("unknown node " + id);
        return n;
    }

    public Optional<SimNode> nodeOwnedBy(String vpa) {
        return nodes.values().stream().filter(n -> vpa.equals(n.ownerVpa)).findFirst();
    }

    public void log(String kind, String text, String hash) {
        events.addFirst(new Event(tick, kind, text, hash));
        while (events.size() > 200) events.removeLast();
    }

    public Collection<SimNode> nodes() { return nodes.values(); }
    public List<Event> events() { return List.copyOf(events); }
    public List<Contact> contacts() { return List.copyOf(lastContacts); }
    public Stats stats() { return stats; }
    public int tick() { return tick; }
    public MeshConfig config() { return cfg; }

    /** Every copy of a packet currently in the mesh. */
    public int copiesInMesh(String hash) {
        int n = 0;
        for (SimNode s : nodes.values()) for (Carried c : s.buffer.values()) if (c.hash().equals(hash)) n++;
        return n;
    }

    public Optional<Carried> anyCarried(java.util.function.Predicate<Carried> p) {
        for (SimNode s : nodes.values()) for (Carried c : s.buffer.values()) if (p.test(c)) return Optional.of(c);
        return Optional.empty();
    }
}
