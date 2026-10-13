package com.demo.upimesh.unit;

import com.demo.upimesh.config.MeshPayProperties;
import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.crypto.HybridCipher;
import com.demo.upimesh.protocol.*;
import com.demo.upimesh.service.ApiException;
import com.demo.upimesh.service.BridgeGate;
import com.demo.upimesh.sim.OfflineVerifier;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/** Fast tests with no Spring context and no database. */
class CryptoAndGateTest {

    @Test
    void hybridCipherRoundTripsAndBindsTheKeyId() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair rsa = g.generateKeyPair();
        byte[] msg = "pay bob 100".getBytes(StandardCharsets.UTF_8);

        byte[] wire = HybridCipher.encrypt(msg, rsa.getPublic(), "enc-a");
        assertThat(HybridCipher.decrypt(wire, rsa.getPrivate(), "enc-a")).isEqualTo(msg);
        assertThatThrownBy(() -> HybridCipher.decrypt(wire, rsa.getPrivate(), "enc-b"))
                .isInstanceOf(GeneralSecurityException.class);
        assertThatThrownBy(() -> HybridCipher.decrypt(new byte[10], rsa.getPrivate(), "enc-a"))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void canonicalFormsAreUnambiguous() {
        PaymentInstruction a = instr("a@x", "b@x", "1.50");
        PaymentInstruction b = instr("a@x", "b@x", "1.5");
        assertThat(a.canonical()).isEqualTo(b.canonical()); // same money, same bytes
        assertThat(instr("a@x", "b@x", "1.51").canonical()).isNotEqualTo(a.canonical());
        assertThat(instr("a@x", "b@x", "1.505").problems()).contains("bad_amount");
        assertThat(instr("a\n@x", "b@x", "1.00").problems()).contains("bad_sender_vpa");
    }

    @Test
    void receiverDetectsATamperedIouOffline() {
        KeyPair server = Crypto.newEcKeyPair();
        KeyPair device = Crypto.newEcKeyPair();
        long now = System.currentTimeMillis();
        WalletCertificate unsigned = new WalletCertificate(UUID.randomUUID().toString(), "alice@bank", "dev-1",
                Crypto.b64(device.getPublic().getEncoded()), new BigDecimal("500.00"), new BigDecimal("200.00"),
                0, now, now + 86_400_000, "sig-k1", null);
        WalletCertificate cert = unsigned.withSignature("sig-k1", Crypto.sign(server.getPrivate(), unsigned.canonical()));
        Map<String, PublicKey> keys = Map.of("sig-k1", server.getPublic());

        PaymentInstruction in = new PaymentInstruction("alice@bank", "bob@bank", new BigDecimal("100.00"), "dev-1", 0,
                UUID.randomUUID().toString(), now, cert.certId());
        SignedEnvelope env = new SignedEnvelope(in, Crypto.sign(device.getPrivate(), in.canonical()));
        assertThat(OfflineVerifier.checkIou(new OfflineIou(env, cert), "bob@bank", keys, now)).isEmpty();

        // sender edits the amount after signing
        PaymentInstruction inflated = new PaymentInstruction("alice@bank", "bob@bank", new BigDecimal("150.00"), "dev-1", 0,
                in.nonce(), now, cert.certId());
        assertThat(OfflineVerifier.checkIou(new OfflineIou(new SignedEnvelope(inflated, env.signature()), cert),
                "bob@bank", keys, now)).contains("bad_signature");

        // sender inflates their own certificate limit
        WalletCertificate fakeCert = new WalletCertificate(cert.certId(), cert.vpa(), cert.deviceId(), cert.devicePublicKey(),
                new BigDecimal("50000.00"), cert.perTxnCap(), 0, cert.issuedAt(), cert.expiresAt(), "sig-k1", cert.signature());
        assertThat(OfflineVerifier.checkIou(new OfflineIou(env, fakeCert), "bob@bank", keys, now)).contains("bad_certificate");

        // expired wallet
        assertThat(OfflineVerifier.checkIou(new OfflineIou(env, cert), "bob@bank", keys, now + 2 * 86_400_000L))
                .contains("wallet_expired");
    }

    @Test
    void bridgeGateAuthenticatesByTokenAndRateLimits() {
        MeshPayProperties props = new MeshPayProperties(Duration.ofHours(72), Duration.ofMinutes(5),
                new MeshPayProperties.Idempotency("memory", Duration.ofSeconds(60), Duration.ofDays(10)),
                new MeshPayProperties.Wallet(new BigDecimal("2000"), new BigDecimal("500"), Duration.ofDays(7)),
                new MeshPayProperties.Bridge(Map.of("b1", "token-for-bridge-one-xyz", "short", "tooShort"), 3, 1),
                new MeshPayProperties.Keys("x", 2048, Duration.ofDays(8)));
        BridgeGate gate = new BridgeGate(props, Clock.systemUTC());

        assertThat(gate.authenticate("Bearer token-for-bridge-one-xyz")).isEqualTo("b1");
        assertThatThrownBy(() -> gate.authenticate("Bearer tooShort")).isInstanceOf(ApiException.class); // weak tokens ignored
        assertThatThrownBy(() -> gate.authenticate(null)).isInstanceOf(ApiException.class);

        gate.checkRate("b1");
        gate.checkRate("b1");
        gate.checkRate("b1");
        assertThatThrownBy(() -> gate.checkRate("b1"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.code()).isEqualTo("rate_limited"));
    }

    private static PaymentInstruction instr(String from, String to, String amt) {
        return new PaymentInstruction(from, to, new BigDecimal(amt), "dev-1", 1,
                "0123456789abcdef-nonce", 1_700_000_000_000L, "00000000-0000-0000-0000-000000000000");
    }
}
