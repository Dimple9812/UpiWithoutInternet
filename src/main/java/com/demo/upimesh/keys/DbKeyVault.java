package com.demo.upimesh.keys;

import com.demo.upimesh.config.MeshPayProperties;
import com.demo.upimesh.crypto.Crypto;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Key vault backed by the {@code server_keys} table. Private keys are stored wrapped
 * with AES-256-GCM under a master key that comes from the environment
 * ({@code MESHPAY_MASTER_KEY}), never from the database — so a DB dump alone does
 * not leak them. Keys survive restarts, which is what keeps in-flight mesh packets
 * decryptable (the original demo generated a new key on every boot).
 */
@Component
public class DbKeyVault implements KeyVault {

    private static final Logger log = LoggerFactory.getLogger(DbKeyVault.class);

    private final ServerKeyRepository repo;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final MeshPayProperties.Keys cfg;
    private final SecretKeySpec masterKey;

    private final Map<String, ServerKeyEntity> entities = new ConcurrentHashMap<>();
    private final Map<String, PrivateKey> privateKeys = new ConcurrentHashMap<>();

    public DbKeyVault(ServerKeyRepository repo, TransactionTemplate tx, Clock clock, MeshPayProperties props) {
        this.repo = repo;
        this.tx = tx;
        this.clock = clock;
        this.cfg = props.keys();
        if (cfg.masterKey() == null || cfg.masterKey().isBlank()) {
            throw new IllegalStateException(
                    "meshpay.keys.master-key is not set. Provide a base64 32-byte key via MESHPAY_MASTER_KEY " +
                    "(e.g. `openssl rand -base64 32`).");
        }
        byte[] mk = Crypto.unb64(cfg.masterKey());
        if (mk.length != 32) throw new IllegalStateException("meshpay.keys.master-key must decode to 32 bytes");
        this.masterKey = new SecretKeySpec(mk, "AES");
    }

    @PostConstruct
    void ensureActiveKeys() {
        for (Purpose p : Purpose.values()) {
            if (repo.findFirstByPurposeAndStatus(p, "ACTIVE").isEmpty()) {
                try {
                    tx.executeWithoutResult(s -> repo.saveAndFlush(generate(p)));
                    log.info("Generated initial {} key", p);
                } catch (DataIntegrityViolationException raced) {
                    log.info("Another instance created the initial {} key", p); // unique(active per purpose)
                }
            }
        }
    }

    // ------------------------------------------------------------------ queries

    @Override
    public PublicKeyInfo activeKey(Purpose purpose) {
        ServerKeyEntity e = repo.findFirstByPurposeAndStatus(purpose, "ACTIVE")
                .orElseThrow(() -> new IllegalStateException("no active " + purpose + " key"));
        entities.put(e.getKeyId(), e);
        return info(e);
    }

    @Override
    public Optional<PrivateKey> decryptionKey(String keyId) {
        return entity(keyId)
                .filter(e -> e.getPurpose() == Purpose.ENCRYPTION)
                .filter(e -> "ACTIVE".equals(e.getStatus())
                        || (e.getRetiredAt() != null
                            && e.getRetiredAt().plus(cfg.retiredKeyGrace()).isAfter(clock.instant())))
                .map(this::privateKey);
    }

    @Override
    public Signed sign(Function<String, String> canonicalForKeyId) {
        PublicKeyInfo active = activeKey(Purpose.SIGNING);
        PrivateKey pk = privateKey(entities.get(active.keyId()));
        return new Signed(active.keyId(), Crypto.sign(pk, canonicalForKeyId.apply(active.keyId())));
    }

    @Override
    public Optional<PublicKey> signingPublicKey(String keyId) {
        return entity(keyId)
                .filter(e -> e.getPurpose() == Purpose.SIGNING)
                .map(e -> Crypto.ecPublicKey(e.getPublicKey()));
    }

    @Override
    public List<PublicKeyInfo> publicKeys() {
        return repo.findAllByOrderByCreatedAtDesc().stream().map(DbKeyVault::info).toList();
    }

    // ------------------------------------------------------------------ rotation

    @Override
    public PublicKeyInfo rotate(Purpose purpose) {
        ServerKeyEntity created = tx.execute(s -> {
            repo.findFirstByPurposeAndStatus(purpose, "ACTIVE").ifPresent(old -> {
                old.retire(clock.instant());
                repo.saveAndFlush(old);
                entities.put(old.getKeyId(), old);
            });
            return repo.saveAndFlush(generate(purpose));
        });
        log.atInfo().addKeyValue("purpose", purpose).addKeyValue("keyId", created.getKeyId())
                .log("Rotated server key");
        return info(created);
    }

    @Override
    public void reload() {
        entities.clear();
        privateKeys.clear();
    }

    // ------------------------------------------------------------------ internals

    private Optional<ServerKeyEntity> entity(String keyId) {
        if (keyId == null) return Optional.empty();
        ServerKeyEntity cached = entities.get(keyId);
        if (cached != null && "ACTIVE".equals(cached.getStatus())) {
            // re-read: another instance may have rotated it
            Optional<ServerKeyEntity> fresh = repo.findById(keyId);
            fresh.ifPresent(f -> entities.put(keyId, f));
            return fresh;
        }
        if (cached != null) return Optional.of(cached);
        Optional<ServerKeyEntity> found = repo.findById(keyId);
        found.ifPresent(f -> entities.put(keyId, f));
        return found;
    }

    private PrivateKey privateKey(ServerKeyEntity e) {
        return privateKeys.computeIfAbsent(e.getKeyId(), id -> {
            byte[] pkcs8 = unwrap(e.getWrappedPrivateKey(), id);
            return e.getPurpose() == Purpose.ENCRYPTION ? Crypto.rsaPrivateKey(pkcs8) : Crypto.ecPrivateKey(pkcs8);
        });
    }

    private ServerKeyEntity generate(Purpose purpose) {
        try {
            String keyId = (purpose == Purpose.ENCRYPTION ? "enc-" : "sig-")
                    + UUID.randomUUID().toString().substring(0, 12);
            KeyPair kp;
            String alg;
            if (purpose == Purpose.ENCRYPTION) {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(cfg.rsaBits(), Crypto.rng());
                kp = g.generateKeyPair();
                alg = "RSA-OAEP-256+A256GCM";
            } else {
                kp = Crypto.newEcKeyPair();
                alg = Crypto.SIGNATURE_ALG;
            }
            return new ServerKeyEntity(keyId, purpose, alg, Crypto.b64(kp.getPublic().getEncoded()),
                    wrap(kp.getPrivate().getEncoded(), keyId), clock.instant());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private String wrap(byte[] secret, String keyId) {
        try {
            byte[] iv = new byte[12];
            Crypto.rng().nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(128, iv));
            c.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(secret);
            return Crypto.b64(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private byte[] unwrap(String wrapped, String keyId) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(Crypto.unb64(wrapped));
            byte[] iv = new byte[12];
            buf.get(iv);
            byte[] ct = new byte[buf.remaining()];
            buf.get(ct);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(128, iv));
            c.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(ct);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("cannot unwrap key " + keyId + " (wrong MESHPAY_MASTER_KEY?)", ex);
        }
    }

    private static PublicKeyInfo info(ServerKeyEntity e) {
        return new PublicKeyInfo(e.getKeyId(), e.getPurpose(), e.getAlgorithm(), e.getPublicKey(),
                e.getStatus(), e.getCreatedAt(), e.getRetiredAt());
    }
}
