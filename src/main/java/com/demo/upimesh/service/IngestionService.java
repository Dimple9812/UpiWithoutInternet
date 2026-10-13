package com.demo.upimesh.service;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.crypto.HybridCipher;
import com.demo.upimesh.domain.Payment;
import com.demo.upimesh.domain.PaymentRepository;
import com.demo.upimesh.idempotency.IdempotencyStore;
import com.demo.upimesh.idempotency.IdempotencyStore.State;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.SettlementReceipt;
import com.demo.upimesh.protocol.SignedEnvelope;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.NonTransientDataAccessException;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

/**
 * The bridge upload pipeline for one packet:
 *
 * <pre>
 *  hash(ciphertext) → idempotency claim → DB backstop lookup → decrypt by keyId
 *     → SettlementService.process (signature, freshness, wallet, counter, limits, money)
 *     → mark final state → signed receipt
 * </pre>
 *
 * Outcomes:
 * <ul>
 *   <li>SETTLED / REJECTED — final, with a server-signed receipt (REJECTED without a receipt only
 *       when the packet could not be decrypted, since then nobody can be told)</li>
 *   <li>DUPLICATE — already handled (or being handled) via another bridge; the original receipt if known</li>
 *   <li>RETRY — transient failure; the bridge must keep the packet and try again later</li>
 * </ul>
 * Bad payments never throw to the client.
 */
@Service
public class IngestionService {

    private static final Logger log = LoggerFactory.getLogger(IngestionService.class);

    public enum Outcome { SETTLED, REJECTED, DUPLICATE, RETRY }

    public record IngestResult(Outcome outcome, String packetHash, String reason, SettlementReceipt receipt) {}

    private final IdempotencyStore idempotency;
    private final PaymentRepository payments;
    private final SettlementService settlement;
    private final KeyVault vault;
    private final MeterRegistry metrics;
    private final Clock clock;
    private final ObjectMapper json;

    public IngestionService(IdempotencyStore idempotency, PaymentRepository payments, SettlementService settlement,
                            KeyVault vault, MeterRegistry metrics, Clock clock, ObjectMapper mapper) {
        this.idempotency = idempotency;
        this.payments = payments;
        this.settlement = settlement;
        this.vault = vault;
        this.metrics = metrics;
        this.clock = clock;
        // strict copy: unknown fields inside the encrypted payload are an error
        this.json = mapper.copy().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    public IngestResult ingest(MeshPacket packet, String bridgeId, int hopCount) {
        byte[] wire;
        try {
            wire = Crypto.unb64(packet.ciphertext());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("bad_ciphertext", "ciphertext is not valid base64");
        }
        // Hash the decoded bytes, not the base64 text, so alternative encodings of the
        // same ciphertext cannot dodge the idempotency check.
        String hash = Crypto.sha256Hex(wire);
        IngestResult r = run(packet, wire, hash, bridgeId, Math.max(0, Math.min(hopCount, 64)));
        count(r);
        return r;
    }

    public Optional<SettlementReceipt> receipt(String packetHash) {
        return payments.findByPacketHash(packetHash).map(Payment::receipt);
    }

    // ----------------------------------------------------------------- pipeline

    private IngestResult run(MeshPacket packet, byte[] wire, String hash, String bridgeId, int hops) {
        IdempotencyStore.Claim claim;
        try {
            claim = idempotency.claim(hash);
        } catch (RuntimeException storeDown) {
            log.atError().addKeyValue("packetHash", hash).setCause(storeDown).log("Idempotency store unavailable");
            return new IngestResult(Outcome.RETRY, hash, "idempotency_store_unavailable", null);
        }
        if (!claim.acquired()) {
            log.atInfo().addKeyValue("packetHash", hash).addKeyValue("bridge", bridgeId)
                    .addKeyValue("state", claim.current()).log("Duplicate packet dropped");
            return new IngestResult(Outcome.DUPLICATE, hash, "already_" + claim.current().name().toLowerCase(),
                    safeReceipt(hash));
        }

        try {
            // DB backstop: the idempotency store may have been wiped (restart / eviction).
            Optional<Payment> already = payments.findByPacketHash(hash);
            if (already.isPresent()) {
                idempotency.complete(hash, finalState(already.get()));
                return new IngestResult(Outcome.DUPLICATE, hash, "already_recorded", already.get().receipt());
            }

            Optional<PrivateKey> key = vault.decryptionKey(packet.keyId());
            if (key.isEmpty()) return rejectedUnrecorded(hash, "unknown_or_expired_key");

            byte[] plaintext;
            try {
                plaintext = HybridCipher.decrypt(wire, key.get(), packet.keyId());
            } catch (GeneralSecurityException | RuntimeException e) {
                log.atWarn().addKeyValue("packetHash", hash).addKeyValue("bridge", bridgeId)
                        .log("Decryption failed (tampered or junk packet)");
                return rejectedUnrecorded(hash, "decryption_failed");
            }

            SignedEnvelope env;
            try {
                env = json.readValue(plaintext, SignedEnvelope.class);
                if (env.instruction() == null || env.signature() == null) throw new IllegalArgumentException();
            } catch (Exception e) {
                return finish(hash, settlement.rejectUnparsed(hash, bridgeId, hops, "malformed_payload"));
            }

            return finish(hash, settleWithBackstop(hash, env, bridgeId, hops));

        } catch (NonTransientDataAccessException | IllegalArgumentException | IllegalStateException permanent) {
            // Bugs or data problems that will not fix themselves; still release so an operator can replay.
            log.atError().addKeyValue("packetHash", hash).setCause(permanent).log("Ingestion failed");
            idempotency.releaseForRetry(hash);
            return new IngestResult(Outcome.RETRY, hash, "internal_error", null);
        } catch (RuntimeException transientFailure) {
            // DB down, lock timeout, connection reset...: let the next copy of the packet try again.
            log.atWarn().addKeyValue("packetHash", hash).addKeyValue("error", transientFailure.getClass().getSimpleName())
                    .log("Transient failure, packet released for retry");
            idempotency.releaseForRetry(hash);
            return new IngestResult(Outcome.RETRY, hash, "transient_error", null);
        }
    }

    /**
     * A unique-constraint violation means another instance (or a Redis-less retry)
     * got there first: report the existing row as a duplicate, or re-run once so the
     * counter check produces the right answer.
     */
    private SettlementService.Result settleWithBackstop(String hash, SignedEnvelope env, String bridgeId, int hops) {
        try {
            return settlement.process(hash, env, bridgeId, hops);
        } catch (DataIntegrityViolationException race) {
            Optional<Payment> existing = payments.findByPacketHash(hash);
            if (existing.isPresent()) return new SettlementService.Result(existing.get(), true);
            return settlement.process(hash, env, bridgeId, hops);
        }
    }

    private IngestResult finish(String hash, SettlementService.Result r) {
        Payment p = r.payment();
        idempotency.complete(hash, finalState(p));
        if (r.duplicate()) {
            return new IngestResult(Outcome.DUPLICATE, hash, "already_recorded", p.receipt());
        }
        if (p.getStatus() == Payment.Status.SETTLED) {
            if (p.getSignedAt() != null) {
                metrics.timer("meshpay.delivery.latency")
                        .record(Duration.between(p.getSignedAt(), clock.instant()));
            }
            metrics.summary("meshpay.packet.hops").record(p.getHopCount());
            return new IngestResult(Outcome.SETTLED, hash, null, p.receipt());
        }
        return new IngestResult(Outcome.REJECTED, hash, p.getReason(), p.receipt());
    }

    private IngestResult rejectedUnrecorded(String hash, String reason) {
        idempotency.complete(hash, State.REJECTED);
        return new IngestResult(Outcome.REJECTED, hash, reason, null);
    }

    private SettlementReceipt safeReceipt(String hash) {
        try {
            return receipt(hash).orElse(null);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static State finalState(Payment p) {
        return p.getStatus() == Payment.Status.SETTLED ? State.SETTLED : State.REJECTED;
    }

    private void count(IngestResult r) {
        metrics.counter("meshpay.ingest", "outcome", r.outcome().name(),
                "reason", r.reason() == null ? "none" : r.reason()).increment();
    }
}
