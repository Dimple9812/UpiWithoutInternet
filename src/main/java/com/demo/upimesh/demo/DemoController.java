package com.demo.upimesh.demo;

import com.demo.upimesh.domain.*;
import com.demo.upimesh.idempotency.IdempotencyStore;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.WalletCertificate;
import com.demo.upimesh.service.ApiException;
import com.demo.upimesh.service.IngestionService;
import com.demo.upimesh.service.OnboardingService;
import com.demo.upimesh.service.PinHasher;
import com.demo.upimesh.sim.PhoneClient;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Demo-only endpoints that drive the dashboard. Active only with the {@code demo}
 * profile — never part of the production surface.
 *
 * Each demo user gets a {@link PhoneClient} that onboards exactly like a real phone
 * (device key registration + offline wallet), so packets created here go through the
 * full production verification path.
 */
@RestController
@RequestMapping("/api")
@Profile("demo")
public class DemoController {

    static final String DEMO_PIN = "1234";
    static final int DEFAULT_TTL = 5;

    private final AccountRepository accounts;
    private final PaymentRepository payments;
    private final OnboardingService onboarding;
    private final IngestionService ingestion;
    private final IdempotencyStore idempotency;
    private final KeyVault vault;
    private final MeshSimulatorService mesh;
    private final Clock clock;
    private final Map<String, PhoneClient> phones = new ConcurrentHashMap<>();
    private final Map<String, Integer> initialTtl = new ConcurrentHashMap<>();

    public DemoController(AccountRepository accounts, PaymentRepository payments, OnboardingService onboarding,
                          IngestionService ingestion, IdempotencyStore idempotency, KeyVault vault,
                          MeshSimulatorService mesh, Clock clock) {
        this.accounts = accounts;
        this.payments = payments;
        this.onboarding = onboarding;
        this.ingestion = ingestion;
        this.idempotency = idempotency;
        this.vault = vault;
        this.mesh = mesh;
        this.clock = clock;
    }

    @PostConstruct
    void seed() {
        seedAccount("alice@demo", "Alice", "5000.00");
        seedAccount("bob@demo", "Bob", "1000.00");
        seedAccount("carol@demo", "Carol", "2500.00");
        seedAccount("dave@demo", "Dave", "500.00");
    }

    private void seedAccount(String vpa, String name, String balance) {
        if (accounts.existsById(vpa)) return;
        PinHasher.Hashed h = PinHasher.hash(DEMO_PIN);
        accounts.save(new Account(vpa, name, new BigDecimal(balance), h.salt(), h.hash()));
    }

    // ------------------------------------------------------------------ demo send

    public record DemoSendRequest(String senderVpa, String receiverVpa, BigDecimal amount, String pin,
                                  Integer ttl, String startDevice) {}

    @PostMapping("/demo/send")
    public ResponseEntity<?> send(@RequestBody DemoSendRequest req) {
        PhoneClient phone = phoneFor(req.senderVpa(), req.pin());
        int ttl = req.ttl() == null ? DEFAULT_TTL : req.ttl();
        PhoneClient.PaymentBundle b;
        try {
            b = phone.pay(req.receiverVpa(), req.amount(), ttl);
        } catch (PhoneClient.LocalLimitException e) {
            throw ApiException.unprocessable("local_limit", e.getMessage());
        }
        String start = req.startDevice() == null ? "phone-alice" : req.startDevice();
        mesh.inject(start, b.packet());
        initialTtl.put(b.packet().packetId(), ttl);
        return ResponseEntity.ok(Map.of(
                "packetId", b.packet().packetId(),
                "ciphertextPreview", b.packet().ciphertext().substring(0, 64) + "...",
                "ttl", ttl,
                "counter", b.instruction().counter(),
                "offlineRemaining", phone.localRemaining(),
                "injectedAt", start));
    }

    /**
     * First use of a VPA: register a device key and load a ₹1000 offline wallet, like a real phone would.
     * Demo phone keys live in memory, so after a restart each user gets a new device (like reinstalling
     * the app); the old device's unspent reserve is refunded by the wallet sweeper once it expires.
     */
    private PhoneClient phoneFor(String vpa, String pin) {
        return phones.computeIfAbsent(vpa, v -> {
            String deviceId = "dev-" + v.replaceAll("[^A-Za-z0-9]", "-") + "-" + UUID.randomUUID().toString().substring(0, 6);
            PhoneClient p = new PhoneClient(v, deviceId, clock);
            KeyVault.PublicKeyInfo enc = vault.activeKey(KeyVault.Purpose.ENCRYPTION);
            p.installServerKey(enc.keyId(), enc.publicKey());
            onboarding.registerDevice(v, p.deviceId(), p.publicKeyB64(), pin);
            WalletCertificate cert = onboarding.issueWallet(v, p.deviceId(), new BigDecimal("1000.00"), null, pin);
            p.installWallet(cert);
            return p;
        });
    }

    // ------------------------------------------------------------------ mesh

    @GetMapping("/mesh/state")
    public Map<String, Object> state() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (VirtualDevice d : mesh.getDevices()) {
            list.add(Map.of("deviceId", d.getDeviceId(), "hasInternet", d.hasInternet(),
                    "packetCount", d.packetCount(),
                    "packetIds", d.getHeldPackets().stream().map(p -> p.packetId().substring(0, 8)).toList()));
        }
        return Map.of("devices", list, "idempotencyCacheSize", idempotency.size());
    }

    @PostMapping("/mesh/gossip")
    public MeshSimulatorService.GossipResult gossip() {
        return mesh.gossipOnce();
    }

    @PostMapping("/mesh/flush")
    public Map<String, Object> flush() {
        List<MeshSimulatorService.BridgeUpload> uploads = mesh.collectBridgeUploads();
        List<Map<String, Object>> results = Collections.synchronizedList(new ArrayList<>());
        uploads.parallelStream().forEach(up -> {
            MeshPacket p = up.packet();
            int hops = initialTtl.getOrDefault(p.packetId(), DEFAULT_TTL) - p.ttl();
            IngestionService.IngestResult r = ingestion.ingest(p, up.bridgeNodeId(), hops);
            if (r.outcome() != IngestionService.Outcome.RETRY) mesh.purge(p.packetId()); // receipt gossiped back
            results.add(Map.of("bridgeNode", up.bridgeNodeId(), "packetId", p.packetId().substring(0, 8),
                    "outcome", r.outcome().name(), "reason", r.reason() == null ? "" : r.reason()));
        });
        return Map.of("uploadsAttempted", uploads.size(), "results", results);
    }

    @PostMapping("/mesh/reset")
    public Map<String, Object> reset() {
        mesh.reset();
        idempotency.clearAll();
        return Map.of("status", "mesh and idempotency cache cleared");
    }

    // ------------------------------------------------------------------ views

    @GetMapping("/accounts")
    public List<Account> accounts() { return accounts.findAll(); }

    @GetMapping("/transactions")
    public List<Payment> transactions() { return payments.findTop20ByOrderByIdDesc(); }
}
