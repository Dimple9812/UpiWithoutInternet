package com.demo.upimesh.unit;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.demo.mesh.MeshConfig;
import com.demo.upimesh.demo.mesh.MeshEngine;
import com.demo.upimesh.demo.mesh.SimNode;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.SettlementReceipt;
import com.demo.upimesh.service.IngestionService.IngestResult;
import com.demo.upimesh.service.IngestionService.Outcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/** Mesh mechanics with pinned phones and a fake backend: fully deterministic. */
class MeshEngineTest {

    // range 17, coverage from x=84, buffer 12, 8 copies, lifetime 300
    private final MeshConfig cfg = MeshConfig.defaults();
    private final List<String> uploadedBy = new ArrayList<>();
    private Function<MeshPacket, Outcome> backend = p -> Outcome.SETTLED;
    private MeshEngine engine;

    @BeforeEach
    void setUp() {
        engine = new MeshEngine(cfg, 7, (packet, bridge, hops) -> {
            uploadedBy.add(bridge);
            Outcome o = backend.apply(packet);
            String hash = MeshEngine.hashOf(packet);
            SettlementReceipt r = o == Outcome.RETRY ? null : receipt(hash);
            return new IngestResult(o, hash, null, r);
        });
        for (String id : List.of("alice", "bob", "relay", "far")) engine.addNode(id, id, id.equals("alice") ? "alice@demo" : null);
        engine.place("alice", 10, 10, 100);
        engine.place("bob", 80, 50, 100);     // nobody near bob
        engine.place("relay", 20, 10, 100);   // 10 units from alice
        engine.place("far", 50, 40, 100);
    }

    @Test
    void sprayPhaseHandsOverHalfTheCopies() {
        MeshPacket p = packet(8);
        engine.inject("alice", p);
        engine.step();

        assertThat(carried("alice", p).copies()).isEqualTo(4);
        assertThat(carried("relay", p).copies()).isEqualTo(4);
        assertThat(carried("relay", p).hops()).isEqualTo(1);
        assertThat(carried("relay", p).packet().ttl()).isEqualTo(7);
    }

    @Test
    void waitPhaseOnlyDeliversToAPhoneWithInternet() {
        MeshPacket p = packet(8);
        engine.injectAsRelay("alice", p, 1); // last copy
        engine.step();
        assertThat(engine.node("relay").buffer()).isEmpty();

        engine.place("relay", 86, 10, 100); // relay now in 4G...
        engine.place("alice", 80, 10, 100); // ...and in range of alice
        engine.step();
        assertThat(uploadedBy).containsExactly("relay");
    }

    @Test
    void receiptsSpreadAndPurgeEveryCopy() {
        MeshPacket p = packet(8);
        engine.inject("alice", p);
        engine.step();                                  // relay gets 4 copies
        engine.place("relay", 90, 10, 100);             // relay walks into 4G and uploads
        engine.step();
        String hash = MeshEngine.hashOf(p);
        assertThat(engine.node("relay").receipts()).containsKey(hash);
        assertThat(engine.node("alice").buffer()).isNotEmpty(); // alice hasn't heard yet

        engine.place("relay", 15, 10, 100);             // relay comes back near alice
        engine.step();
        assertThat(engine.node("alice").receipts()).containsKey(hash);
        assertThat(engine.node("alice").buffer()).isEmpty();
        assertThat(engine.stats().settled).isEqualTo(1);
        assertThat(engine.stats().purgedByReceipt).isGreaterThanOrEqualTo(1);
    }

    @Test
    void fullBufferEvictsTheOldestStrangerPacketButNeverItsOwn() {
        for (int i = 0; i < cfg.bufferCapacity(); i++) engine.injectAsRelay("relay", packet(8), 4);
        String oldest = engine.node("relay").buffer().keySet().iterator().next();

        engine.inject("alice", packet(8));
        engine.step();
        assertThat(engine.node("relay").buffer()).hasSize(cfg.bufferCapacity()).doesNotContainKey(oldest);
        assertThat(engine.stats().evicted).isGreaterThanOrEqualTo(1);

        // a phone whose buffer is all its own packets refuses strangers' packets
        for (int i = 0; i < cfg.bufferCapacity(); i++) engine.inject("far", packet(8));
        engine.injectAsRelay("relay", packet(8), 8);
        engine.place("relay", 55, 40, 100);
        engine.step();
        assertThat(engine.node("far").buffer().values()).allMatch(SimNode.Carried::ownPacket);
        assertThat(engine.stats().refused).isGreaterThanOrEqualTo(1);
    }

    @Test
    void packetsExpire() {
        engine.inject("far", packet(8));
        for (int i = 0; i <= cfg.packetLifetime(); i++) engine.step();
        assertThat(engine.node("far").buffer()).isEmpty();
        assertThat(engine.stats().expired).isEqualTo(1);
    }

    @Test
    void lowBatteryScansLessAndCriticalBatteryTurnsTheRadioOff() {
        engine.place("relay", 20, 10, 10); // low
        int scans = 0;
        for (int i = 0; i < 9; i++) { engine.step(); if (engine.node("relay").scanning()) scans++; }
        assertThat(scans).isEqualTo(3);

        engine.place("relay", 20, 10, 2);  // critical
        engine.inject("alice", packet(8));
        engine.step();
        assertThat(engine.node("relay").radioOn()).isFalse();
        assertThat(engine.node("relay").buffer()).isEmpty();
    }

    @Test
    void retryKeepsThePacketForLater() {
        backend = p -> Outcome.RETRY;
        engine.place("bob", 90, 50, 100);
        MeshPacket p = packet(8);
        engine.injectAsRelay("bob", p, 1);
        engine.step();
        assertThat(engine.node("bob").buffer()).containsKey(p.packetId());
        assertThat(engine.stats().retries).isEqualTo(1);

        backend = q -> Outcome.SETTLED;
        engine.step();
        assertThat(engine.node("bob").buffer()).isEmpty();
    }

    @Test
    void maliciousPhoneIgnoresReceiptsSoReplaysKeepCirculating() {
        engine.node("relay").setMalicious(true);
        MeshPacket p = packet(8);
        engine.injectAsRelay("relay", p, 4);
        engine.place("bob", 22, 10, 100);           // honest phone next to the attacker...
        engine.node("bob").receipts().put(MeshEngine.hashOf(p), receipt(MeshEngine.hashOf(p)));
        engine.step();
        assertThat(engine.node("bob").buffer()).isEmpty(); // ...refuses a packet it knows is settled
        assertThat(engine.node("relay").buffer()).containsKey(p.packetId());
    }

    private static SettlementReceipt receipt(String hash) {
        return new SettlementReceipt(hash, "SETTLED", null, "alice@demo", "bob@demo", new BigDecimal("10.00"),
                "dev", 1L, "c", 0, "k", "sig");
    }

    private SimNode.Carried carried(String node, MeshPacket p) {
        return engine.node(node).buffer().get(p.packetId());
    }

    private static MeshPacket packet(int ttl) {
        byte[] junk = new byte[64];
        Crypto.rng().nextBytes(junk);
        return new MeshPacket(UUID.randomUUID().toString(), "enc-test", ttl, 1, Crypto.b64(junk));
    }
}
