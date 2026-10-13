package com.demo.upimesh.sim;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.crypto.HybridCipher;
import com.demo.upimesh.protocol.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.util.UUID;

/**
 * Reference implementation of the PHONE side of the protocol, in plain Java so it
 * ports 1:1 to the Android app (where the key pair lives in the Android Keystore
 * instead of memory). The demo simulator and the tests use it to behave exactly
 * like a real sender.
 *
 * Offline it enforces the local wallet rules (amount ≤ per-txn cap, amount ≤
 * remaining offline balance), signs, encrypts, and returns both the mesh packet and
 * the IOU to hand to the receiver.
 */
public class PhoneClient {

    public record PaymentBundle(MeshPacket packet, OfflineIou iou, PaymentInstruction instruction) {}

    public static class LocalLimitException extends RuntimeException {
        public LocalLimitException(String m) { super(m); }
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final String vpa;
    private final String deviceId;
    private final KeyPair deviceKeys;
    private final Clock clock;

    private String serverEncKeyId;
    private PublicKey serverEncKey;
    private WalletCertificate wallet;
    private long nextCounter;
    private BigDecimal localRemaining = BigDecimal.ZERO;

    public PhoneClient(String vpa, String deviceId, Clock clock) {
        this(vpa, deviceId, Crypto.newEcKeyPair(), clock);
    }

    public PhoneClient(String vpa, String deviceId, KeyPair keys, Clock clock) {
        this.vpa = vpa;
        this.deviceId = deviceId;
        this.deviceKeys = keys;
        this.clock = clock;
    }

    // ---------------------------------------------------------- online setup

    public String vpa() { return vpa; }
    public String deviceId() { return deviceId; }
    public String publicKeyB64() { return Crypto.b64(deviceKeys.getPublic().getEncoded()); }
    public KeyPair keys() { return deviceKeys; }
    public WalletCertificate wallet() { return wallet; }
    public BigDecimal localRemaining() { return localRemaining; }
    public long nextCounter() { return nextCounter; }

    public void installServerKey(String keyId, String rsaPublicKeyB64) {
        this.serverEncKeyId = keyId;
        this.serverEncKey = Crypto.rsaPublicKey(rsaPublicKeyB64);
    }

    public void installWallet(WalletCertificate cert) {
        if (!cert.deviceId().equals(deviceId) || !cert.devicePublicKey().equals(publicKeyB64())) {
            throw new IllegalArgumentException("certificate is for a different device");
        }
        this.wallet = cert;
        this.localRemaining = cert.offlineLimit();
        this.nextCounter = Math.max(nextCounter, cert.counterStart());
    }

    // ---------------------------------------------------------- offline payment

    /** Normal path: enforces local limits and consumes a counter. */
    public PaymentBundle pay(String receiverVpa, BigDecimal amount, int ttl) {
        if (wallet == null) throw new LocalLimitException("no offline wallet loaded");
        if (clock.millis() > wallet.expiresAt()) throw new LocalLimitException("offline wallet expired");
        BigDecimal amt = amount.setScale(2, RoundingMode.UNNECESSARY);
        if (amt.compareTo(wallet.perTxnCap()) > 0) throw new LocalLimitException("over per-transaction cap");
        if (amt.compareTo(localRemaining) > 0) throw new LocalLimitException("not enough offline balance");
        PaymentBundle b = build(receiverVpa, amt, nextCounter, clock.millis(), ttl);
        nextCounter++;
        localRemaining = localRemaining.subtract(amt);
        return b;
    }

    /**
     * Builds a correctly signed packet with chosen counter/time and NO local checks.
     * Models a tampered or cloned wallet app; used by tests and the demo's attack buttons.
     */
    public PaymentBundle forge(String receiverVpa, BigDecimal amount, long counter, long signedAt, int ttl) {
        return build(receiverVpa, amount.setScale(2, RoundingMode.UNNECESSARY), counter, signedAt, ttl);
    }

    /** Encrypts an arbitrary envelope (e.g. signed with the wrong key) — attack simulation. */
    public MeshPacket encryptEnvelope(SignedEnvelope env, int ttl) {
        return packet(env, ttl);
    }

    private PaymentBundle build(String receiverVpa, BigDecimal amount, long counter, long signedAt, int ttl) {
        if (serverEncKey == null) throw new IllegalStateException("server key not installed");
        PaymentInstruction in = new PaymentInstruction(vpa, receiverVpa, amount, deviceId, counter,
                UUID.randomUUID().toString(), signedAt, wallet.certId());
        SignedEnvelope env = new SignedEnvelope(in, Crypto.sign(deviceKeys.getPrivate(), in.canonical()));
        return new PaymentBundle(packet(env, ttl), new OfflineIou(env, wallet), in);
    }

    private MeshPacket packet(SignedEnvelope env, int ttl) {
        try {
            byte[] plaintext = JSON.writeValueAsBytes(env);
            byte[] wire = HybridCipher.encrypt(plaintext, serverEncKey, serverEncKeyId);
            return new MeshPacket(UUID.randomUUID().toString(), serverEncKeyId, ttl, clock.millis(), Crypto.b64(wire));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
