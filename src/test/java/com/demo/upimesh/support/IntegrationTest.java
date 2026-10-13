package com.demo.upimesh.support;

import com.demo.upimesh.domain.*;
import com.demo.upimesh.idempotency.IdempotencyStore;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.WalletCertificate;
import com.demo.upimesh.service.IngestionService;
import com.demo.upimesh.service.OnboardingService;
import com.demo.upimesh.service.PinHasher;
import com.demo.upimesh.sim.PhoneClient;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.math.BigDecimal;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Base class for tests that run against real PostgreSQL + Redis.
 *
 * By default it starts both with Testcontainers (needs Docker). If Docker is not
 * available, point it at running instances instead:
 * <pre>
 *   MESHPAY_TEST_DB_URL=jdbc:postgresql://localhost:5432/meshpay_test
 *   MESHPAY_TEST_DB_USER=meshpay MESHPAY_TEST_DB_PASSWORD=meshpay
 *   MESHPAY_TEST_REDIS_HOST=localhost MESHPAY_TEST_REDIS_PORT=6379
 * </pre>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(IntegrationTest.ClockConfig.class)
public abstract class IntegrationTest {

    public static final String PIN = "4321";

    private static PostgreSQLContainer<?> postgres;
    private static GenericContainer<?> redis;

    @DynamicPropertySource
    static void infra(DynamicPropertyRegistry r) {
        String dbUrl = System.getenv("MESHPAY_TEST_DB_URL");
        if (dbUrl != null) {
            r.add("spring.datasource.url", () -> dbUrl);
            r.add("spring.datasource.username", () -> env("MESHPAY_TEST_DB_USER", "meshpay"));
            r.add("spring.datasource.password", () -> env("MESHPAY_TEST_DB_PASSWORD", "meshpay"));
            r.add("spring.data.redis.host", () -> env("MESHPAY_TEST_REDIS_HOST", "localhost"));
            r.add("spring.data.redis.port", () -> env("MESHPAY_TEST_REDIS_PORT", "6379"));
            return;
        }
        synchronized (IntegrationTest.class) {
            if (postgres == null) {
                postgres = new PostgreSQLContainer<>("postgres:16-alpine");
                postgres.start();
                redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
                redis.start();
            }
        }
        r.add("spring.datasource.url", postgres::getJdbcUrl);
        r.add("spring.datasource.username", postgres::getUsername);
        r.add("spring.datasource.password", postgres::getPassword);
        r.add("spring.data.redis.host", redis::getHost);
        r.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    }

    private static String env(String k, String def) {
        String v = System.getenv(k);
        return v == null ? def : v;
    }

    @TestConfiguration
    static class ClockConfig {
        @Bean @Primary
        MutableClock testClock() { return new MutableClock(); }
    }

    @Autowired protected MutableClock clock;
    @Autowired protected AccountRepository accounts;
    @Autowired protected DeviceRepository devices;
    @Autowired protected OfflineWalletRepository wallets;
    @Autowired protected PaymentRepository payments;
    @Autowired protected OnboardingService onboarding;
    @Autowired protected IngestionService ingestion;
    @Autowired protected IdempotencyStore idempotency;
    @Autowired protected KeyVault vault;

    @AfterEach
    void resetClock() { clock.reset(); }

    // ------------------------------------------------------------------ helpers

    /** A fresh account with a unique VPA so tests never interfere with each other. */
    protected String newAccount(String name, String balance) {
        String vpa = name.toLowerCase() + "-" + UUID.randomUUID().toString().substring(0, 8) + "@test";
        PinHasher.Hashed h = PinHasher.hash(PIN);
        accounts.save(new Account(vpa, name, new BigDecimal(balance), h.salt(), h.hash()));
        return vpa;
    }

    /** Account + registered device + loaded offline wallet, i.e. a phone ready to pay offline. */
    protected PhoneClient onboardedPhone(String name, String balance, String walletAmount, String perTxnCap) {
        String vpa = newAccount(name, balance);
        PhoneClient p = new PhoneClient(vpa, "dev-" + UUID.randomUUID().toString().substring(0, 12), clock);
        KeyVault.PublicKeyInfo enc = vault.activeKey(KeyVault.Purpose.ENCRYPTION);
        p.installServerKey(enc.keyId(), enc.publicKey());
        onboarding.registerDevice(vpa, p.deviceId(), p.publicKeyB64(), PIN);
        WalletCertificate cert = onboarding.issueWallet(vpa, p.deviceId(), new BigDecimal(walletAmount),
                perTxnCap == null ? null : new BigDecimal(perTxnCap), PIN);
        p.installWallet(cert);
        return p;
    }

    protected IngestionService.IngestResult deliver(MeshPacket packet, String bridge) {
        return ingestion.ingest(packet, bridge, 3);
    }

    protected BigDecimal balance(String vpa) {
        return accounts.findById(vpa).orElseThrow().getBalance();
    }

    protected BigDecimal walletRemaining(PhoneClient p) {
        return wallets.findById(p.wallet().certId()).orElseThrow().getRemaining();
    }

    protected Map<String, PublicKey> serverSigningKeys() {
        Map<String, PublicKey> m = new HashMap<>();
        vault.publicKeys().stream().filter(k -> k.purpose() == KeyVault.Purpose.SIGNING)
                .forEach(k -> m.put(k.keyId(), com.demo.upimesh.crypto.Crypto.ecPublicKey(k.publicKey())));
        return m;
    }

    protected static BigDecimal rs(String v) { return new BigDecimal(v); }
}
