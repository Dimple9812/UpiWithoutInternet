package com.demo.upimesh.demo;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.demo.mesh.MeshConfig;
import com.demo.upimesh.demo.mesh.MeshEngine;
import com.demo.upimesh.demo.mesh.SimNode;
import com.demo.upimesh.domain.*;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.*;
import com.demo.upimesh.service.ApiException;
import com.demo.upimesh.service.IngestionService;
import com.demo.upimesh.service.IngestionService.IngestResult;
import com.demo.upimesh.service.OnboardingService;
import com.demo.upimesh.service.PinHasher;
import com.demo.upimesh.sim.OfflineVerifier;
import com.demo.upimesh.sim.PhoneClient;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.security.PublicKey;
import java.time.Clock;
import java.util.*;

/**
 * Drives the demo: a {@link MeshEngine} whose bridges upload through the REAL
 * {@link IngestionService}, plus one {@link PhoneClient} per demo user (registered
 * device key + offline wallet). Every packet in the simulation is a genuine signed and
 * encrypted payment, and every attack is checked by the production pipeline.
 */
@Service
@Profile("demo")
public class SimService {

    private static final Logger log = LoggerFactory.getLogger(SimService.class);

    static final String DEMO_PIN = "1234";

    record DemoUser(String vpa, String name, String balance, String walletAmount) {}

    static final List<DemoUser> USERS = List.of(
            new DemoUser("alice@demo", "Alice", "5000.00", "1000.00"),
            new DemoUser("bob@demo", "Bob", "1000.00", "500.00"),
            new DemoUser("carol@demo", "Carol", "2500.00", "1000.00"),
            new DemoUser("dave@demo", "Dave", "500.00", "300.00"));

    static final List<String> STRANGERS = List.of("Ravi", "Meena", "Arjun", "Priya", "Kabir", "Sana");
    static final String ATTACKER = "Mallory";

    /** What the UI shows for one payment (or attack) as it moves through the system. */
    public static final class PaymentView {
        public String packetId, hash, from, to, kind, iouCheck, serverStatus = "IN_MESH", reason, expected;
        public BigDecimal amount;
        public long counter;
        public int createdTick;
        public Integer serverTick, senderKnewTick, receiverKnewTick;
        public String receiverStatus = "PENDING", senderStatus = "PENDING";
        transient MeshPacket packet;
    }

    private final AccountRepository accounts;
    private final DeviceRepository devices;
    private final OfflineWalletRepository wallets;
    private final OnboardingService onboarding;
    private final IngestionService ingestion;
    private final KeyVault vault;
    private final Clock clock;
    private final TransactionTemplate tx;

    private final MeshEngine engine;
    private final Map<String, PhoneClient> phones = new LinkedHashMap<>();
    private final Map<String, PaymentView> views = new LinkedHashMap<>(); // by hash
    private long seed = 42;

    public SimService(AccountRepository accounts, DeviceRepository devices, OfflineWalletRepository wallets,
                      OnboardingService onboarding, IngestionService ingestion, KeyVault vault, Clock clock,
                      TransactionTemplate tx) {
        this.accounts = accounts;
        this.devices = devices;
        this.wallets = wallets;
        this.onboarding = onboarding;
        this.ingestion = ingestion;
        this.vault = vault;
        this.clock = clock;
        this.tx = tx;
        this.engine = new MeshEngine(MeshConfig.defaults(), seed, this::upload);
    }

    // ------------------------------------------------------------------ startup

    @PostConstruct
    synchronized void init() {
        for (DemoUser u : USERS) seedAccount(u);
        retirePreviousDemoDevices();
        for (DemoUser u : USERS) {
            phones.put(u.vpa(), onboardPhone(u));
            engine.addNode(nodeId(u.vpa()), u.name(), u.vpa());
        }
        for (String s : STRANGERS) engine.addNode(s.toLowerCase(), s, null);
        engine.addNode(ATTACKER.toLowerCase(), ATTACKER, null).setMalicious(true);
        engine.log("info", "11 phones in a basement with no signal. The right edge has 4G.", null);
    }

    private void seedAccount(DemoUser u) {
        if (accounts.existsById(u.vpa())) return;
        PinHasher.Hashed h = PinHasher.hash(DEMO_PIN);
        accounts.save(new Account(u.vpa(), u.name(), new BigDecimal(u.balance()), h.salt(), h.hash()));
    }

    /**
     * Demo phone keys live in memory. After a restart, the previous run's demo devices
     * are revoked and their wallets closed and refunded — safe here because the
     * simulated mesh (and every packet in it) is gone too.
     */
    private void retirePreviousDemoDevices() {
        tx.executeWithoutResult(s -> {
            for (DemoUser u : USERS) {
                for (Device d : devices.findAll()) {
                    if (!d.getVpa().equals(u.vpa()) || d.getStatus() == Device.Status.REVOKED) continue;
                    wallets.findFirstByDeviceIdAndStatus(d.getDeviceId(), OfflineWallet.Status.ACTIVE).ifPresent(w -> {
                        OfflineWallet locked = wallets.lockById(w.getCertId()).orElseThrow();
                        Account a = accounts.lockByVpa(u.vpa()).orElseThrow();
                        a.setBalance(a.getBalance().add(locked.getRemaining()));
                        locked.close(clock.instant());
                    });
                    d.setStatus(Device.Status.REVOKED);
                }
            }
        });
    }

    private PhoneClient onboardPhone(DemoUser u) {
        String deviceId = "dev-" + u.name().toLowerCase() + "-" + UUID.randomUUID().toString().substring(0, 6);
        PhoneClient p = new PhoneClient(u.vpa(), deviceId, clock);
        KeyVault.PublicKeyInfo enc = vault.activeKey(KeyVault.Purpose.ENCRYPTION);
        p.installServerKey(enc.keyId(), enc.publicKey());
        onboarding.registerDevice(u.vpa(), deviceId, p.publicKeyB64(), DEMO_PIN);
        BigDecimal amount = new BigDecimal(u.walletAmount()).min(accounts.findById(u.vpa()).orElseThrow().getBalance());
        if (amount.signum() > 0) {
            p.installWallet(onboarding.issueWallet(u.vpa(), deviceId, amount, null, DEMO_PIN));
        }
        return p;
    }

    // ------------------------------------------------------------------ actions

    public synchronized void step(int n) {
        for (int i = 0; i < Math.max(1, Math.min(n, 200)); i++) {
            engine.step();
            refreshKnowledge();
        }
    }

    public synchronized PaymentView pay(String from, String to, BigDecimal amount) {
        PhoneClient phone = phone(from);
        phone(to); // must be a demo user
        PhoneClient.PaymentBundle b;
        try {
            b = phone.pay(to, amount, 8);
        } catch (PhoneClient.LocalLimitException e) {
            throw ApiException.unprocessable("local_limit", "Phone refused: " + e.getMessage());
        } catch (ArithmeticException e) {
            throw ApiException.badRequest("bad_amount", "Use at most 2 decimal places");
        }
        return track(b, nodeId(from), "Payment", null);
    }

    public synchronized void walkToCoverage(String nodeId) {
        MeshConfig c = engine.config();
        engine.walkTo(nodeId, c.coverageX() + (c.width() - c.coverageX()) / 2, engine.node(nodeId).y());
    }

    public synchronized void reset() {
        seed++;
        engine.reset(seed);
        views.clear();
        engine.log("info", "Mesh reset. Balances and the ledger are kept.", null);
    }

    /**
     * Each attack builds REAL packets the way an attacker could and drops them into the
     * mesh. Nothing is special-cased on the server: the outcome comes from the same
     * pipeline as honest payments.
     */
    public synchronized List<PaymentView> attack(String kind) {
        PhoneClient alice = phone("alice@demo");
        String mallory = ATTACKER.toLowerCase();
        List<PaymentView> out = new ArrayList<>();
        switch (kind) {
            case "tamper" -> {
                // An honest payment, plus a copy Mallory altered by one bit while relaying it.
                PhoneClient.PaymentBundle b = alice.pay("bob@demo", new BigDecimal("50.00"), 8);
                out.add(track(b, nodeId("alice@demo"), "Honest payment (Mallory relays a copy)", "SETTLED"));
                byte[] wire = Crypto.unb64(b.packet().ciphertext());
                wire[wire.length - 20] ^= 0x01;
                MeshPacket bad = new MeshPacket(UUID.randomUUID().toString(), b.packet().keyId(), 7,
                        b.packet().createdAt(), Crypto.b64(wire));
                out.add(trackRaw(bad, mallory, "alice@demo", "bob@demo", new BigDecimal("50.00"), -1,
                        "Tampered copy (1 bit flipped by Mallory)", "REJECTED · decryption_failed", "n/a (relay copy)"));
            }
            case "forge" -> {
                // Mallory claims to be Alice: valid encryption to the PUBLIC server key, wrong signature.
                PaymentInstruction in = new PaymentInstruction("alice@demo", "carol@demo", new BigDecimal("200.00"),
                        alice.deviceId(), alice.nextCounter() + 900, UUID.randomUUID().toString(), clock.millis(),
                        alice.wallet().certId());
                String sig = Crypto.sign(Crypto.newEcKeyPair().getPrivate(), in.canonical());
                SignedEnvelope env = new SignedEnvelope(in, sig);
                MeshPacket p = alice.encryptEnvelope(env, 8);
                String iou = OfflineVerifier.checkIou(new OfflineIou(env, alice.wallet()), "carol@demo",
                        signingKeys(), clock.millis()).map(r -> "fails: " + r).orElse("valid");
                out.add(trackRaw(p, mallory, "alice@demo", "carol@demo", in.amount(), in.counter(),
                        "Forged sender (Mallory signs as Alice)", "REJECTED · bad_signature", iou));
            }
            case "replay" -> {
                PaymentView done = views.values().stream()
                        .filter(v -> "SETTLED".equals(v.serverStatus) && v.packet != null)
                        .reduce((a, b) -> b)
                        .orElseThrow(() -> ApiException.conflict("nothing_to_replay",
                                "Settle a payment first, then replay it."));
                MeshPacket again = new MeshPacket(UUID.randomUUID().toString(), done.packet.keyId(), 7,
                        done.packet.createdAt(), done.packet.ciphertext());
                engine.injectAsRelay(mallory, again, 4);
                PaymentView v = new PaymentView();
                v.packetId = again.packetId(); v.hash = done.hash; v.from = done.from; v.to = done.to;
                v.amount = done.amount; v.counter = done.counter; v.createdTick = engine.tick();
                v.kind = "Replay of a settled payment"; v.expected = "DUPLICATE · no money moves";
                v.iouCheck = "replayed";
                views.put(v.hash + ":replay:" + v.packetId, v);
                engine.log("attack", "Mallory re-broadcasts an already settled packet and walks to 4G to upload it", done.hash);
                walkToCoverage(mallory); // honest phones that hold the receipt refuse it, so she delivers it herself
                out.add(v);
            }
            case "clone" -> {
                // A cloned wallet spends the same counter twice, to two shops.
                long n = alice.nextCounter() + 500 + engine.tick();
                out.add(track(alice.forge("bob@demo", new BigDecimal("100.00"), n, clock.millis(), 8),
                        nodeId("alice@demo"), "Cloned wallet, spend #1 (counter " + n + ")", "one SETTLED"));
                out.add(track(alice.forge("carol@demo", new BigDecimal("100.00"), n, clock.millis(), 8),
                        nodeId("alice@demo"), "Cloned wallet, spend #2 (same counter)", "other REJECTED · counter_reused"));
            }
            case "overspend" -> {
                // A modified app ignores the local limit and signs more than the reserve holds.
                BigDecimal remaining = wallets.findById(alice.wallet().certId()).orElseThrow().getRemaining();
                BigDecimal each = alice.wallet().perTxnCap();
                int count = remaining.divide(each, 0, java.math.RoundingMode.FLOOR).intValue() + 1;
                long base = alice.nextCounter() + 2000 + engine.tick() * 10L;
                for (int i = 0; i < Math.min(count, 6); i++) {
                    out.add(track(alice.forge(i % 2 == 0 ? "dave@demo" : "bob@demo", each, base + i, clock.millis(), 8),
                            nodeId("alice@demo"), "Modified app, payment " + (i + 1) + " of " + count + " (₹" + each + ")",
                            i < count - 1 ? "SETTLED until the reserve runs out" : "last ones REJECTED · offline_limit_exceeded"));
                }
            }
            default -> throw ApiException.badRequest("unknown_attack", "unknown attack " + kind);
        }
        engine.log("attack", describe(kind), null);
        return out;
    }

    private static String describe(String kind) {
        return switch (kind) {
            case "tamper" -> "Attack: Mallory flips one bit in a packet she relays";
            case "forge" -> "Attack: Mallory sends money 'from Alice' without Alice's key";
            case "replay" -> "Attack: Mallory replays a settled packet";
            case "clone" -> "Attack: Alice's cloned wallet spends one counter twice";
            case "overspend" -> "Attack: modified app signs more than Alice's offline reserve";
            default -> "Attack";
        };
    }

    // ------------------------------------------------------------------ tracking

    private PaymentView track(PhoneClient.PaymentBundle b, String atNode, String kind, String expected) {
        engine.inject(atNode, b.packet());
        PhoneClient sender = phones.get(b.instruction().senderVpa());
        String iou = OfflineVerifier.checkIou(b.iou(), b.instruction().receiverVpa(), signingKeys(), clock.millis())
                .map(r -> "fails: " + r).orElse("valid");
        PaymentView v = view(b.packet(), b.instruction().senderVpa(), b.instruction().receiverVpa(),
                b.instruction().amount(), b.instruction().counter(), kind, expected, iou);
        if (sender == null) v.iouCheck = iou;
        return v;
    }

    private PaymentView trackRaw(MeshPacket p, String atNode, String from, String to, BigDecimal amount, long counter,
                                 String kind, String expected, String iou) {
        engine.injectAsRelay(atNode, p, 4);
        engine.log("attack", kind, MeshEngine.hashOf(p));
        return view(p, from, to, amount, counter, kind, expected, iou);
    }

    private PaymentView view(MeshPacket p, String from, String to, BigDecimal amount, long counter,
                             String kind, String expected, String iou) {
        PaymentView v = new PaymentView();
        v.packetId = p.packetId(); v.hash = MeshEngine.hashOf(p); v.from = from; v.to = to; v.amount = amount;
        v.counter = counter; v.createdTick = engine.tick(); v.kind = kind; v.expected = expected; v.iouCheck = iou;
        v.packet = p;
        views.put(v.hash, v);
        return v;
    }

    /** Bridge upload → the real ingestion pipeline. Records the server's first final answer. */
    private IngestResult upload(MeshPacket packet, String bridgeId, int hops) {
        IngestResult r = ingestion.ingest(packet, bridgeId, hops);
        for (PaymentView v : views.values()) {
            if (!v.hash.equals(r.packetHash())) continue;
            boolean isReplay = v.kind.startsWith("Replay");
            if (isReplay && v.packetId.equals(packet.packetId()) && v.serverTick == null) {
                v.serverStatus = r.outcome().name(); v.reason = r.reason(); v.serverTick = engine.tick();
            } else if (!isReplay && v.serverTick == null && r.outcome() != IngestionService.Outcome.RETRY
                    && r.outcome() != IngestionService.Outcome.DUPLICATE) {
                v.serverStatus = r.outcome().name(); v.reason = r.reason(); v.serverTick = engine.tick();
            }
        }
        return r;
    }

    private void refreshKnowledge() {
        for (PaymentView v : views.values()) {
            if (v.kind.startsWith("Replay")) continue;
            engine.nodeOwnedBy(v.to).map(n -> n.receipts().get(v.hash)).ifPresent(r -> {
                if (v.receiverKnewTick == null) { v.receiverKnewTick = engine.tick(); v.receiverStatus = r.status(); }
            });
            engine.nodeOwnedBy(v.from).map(n -> n.receipts().get(v.hash)).ifPresent(r -> {
                if (v.senderKnewTick == null) { v.senderKnewTick = engine.tick(); v.senderStatus = r.status(); }
            });
        }
    }

    // ------------------------------------------------------------------ state for the UI

    public synchronized Map<String, Object> state() {
        MeshConfig c = engine.config();
        List<Map<String, Object>> nodes = new ArrayList<>();
        for (SimNode n : engine.nodes()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", n.id()); m.put("label", n.label()); m.put("owner", n.ownerVpa());
            m.put("x", round(n.x())); m.put("y", round(n.y()));
            m.put("battery", Math.round(n.battery())); m.put("scanning", n.scanning()); m.put("radioOn", n.radioOn());
            m.put("online", engine.online(n)); m.put("malicious", n.malicious());
            m.put("carrying", n.buffer().size()); m.put("receipts", n.receipts().size());
            m.put("packets", n.buffer().values().stream().map(x -> Map.of(
                    "hash", x.hash().substring(0, 8), "copies", x.copies(), "own", x.ownPacket())).toList());
            nodes.add(m);
        }
        MeshEngine.Stats s = engine.stats();
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("created", s.created); stats.put("settled", s.settled); stats.put("rejected", s.rejected);
        stats.put("uploads", s.uploads); stats.put("duplicates", s.duplicates);
        stats.put("duplicateRate", round(s.duplicateRate() * 100));
        stats.put("avgLatencyTicks", round(s.avgLatencyTicks())); stats.put("avgHops", round(s.avgHops()));
        stats.put("transfers", s.transfers); stats.put("receiptTransfers", s.receiptTransfers);
        stats.put("purgedByReceipt", s.purgedByReceipt); stats.put("expired", s.expired);
        stats.put("evicted", s.evicted); stats.put("refused", s.refused); stats.put("retries", s.retries);

        List<Map<String, Object>> people = new ArrayList<>();
        for (PhoneClient p : phones.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            Account a = accounts.findById(p.vpa()).orElseThrow();
            m.put("vpa", p.vpa()); m.put("name", a.getHolderName()); m.put("nodeId", nodeId(p.vpa()));
            m.put("mainBalance", a.getBalance());
            m.put("offlineOnPhone", p.localRemaining());
            m.put("offlineLimit", p.wallet() == null ? BigDecimal.ZERO : p.wallet().offlineLimit());
            m.put("perTxnCap", p.wallet() == null ? BigDecimal.ZERO : p.wallet().perTxnCap());
            m.put("reserveOnServer", p.wallet() == null ? BigDecimal.ZERO
                    : wallets.findById(p.wallet().certId()).map(OfflineWallet::getRemaining).orElse(BigDecimal.ZERO));
            m.put("deviceStatus", devices.findById(p.deviceId()).map(d -> d.getStatus().name()).orElse("?"));
            people.add(m);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tick", engine.tick());
        out.put("config", Map.of("width", c.width(), "height", c.height(), "coverageX", c.coverageX(),
                "radioRange", c.radioRange(), "bufferCapacity", c.bufferCapacity(), "initialCopies", c.initialCopies(),
                "packetLifetime", c.packetLifetime()));
        out.put("nodes", nodes);
        out.put("contacts", engine.contacts());
        out.put("stats", stats);
        out.put("people", people);
        List<PaymentView> pv = new ArrayList<>(views.values());
        Collections.reverse(pv);
        out.put("payments", pv.stream().limit(40).toList());
        out.put("events", engine.events().stream().limit(80).toList());
        return out;
    }

    // ------------------------------------------------------------------ helpers

    private PhoneClient phone(String vpa) {
        PhoneClient p = phones.get(vpa);
        if (p == null) throw ApiException.notFound("unknown_user", "No demo phone for " + vpa);
        if (p.wallet() == null) throw ApiException.conflict("no_wallet", vpa + " has no offline wallet");
        return p;
    }

    private Map<String, PublicKey> signingKeys() {
        Map<String, PublicKey> m = new HashMap<>();
        vault.publicKeys().stream().filter(k -> k.purpose() == KeyVault.Purpose.SIGNING)
                .forEach(k -> m.put(k.keyId(), Crypto.ecPublicKey(k.publicKey())));
        return m;
    }

    static String nodeId(String vpa) { return vpa.substring(0, vpa.indexOf('@')); }

    private static double round(double d) { return Math.round(d * 10) / 10.0; }

    MeshEngine engine() { return engine; }

    synchronized List<PaymentView> viewsForTest() { return List.copyOf(views.values()); }
}
