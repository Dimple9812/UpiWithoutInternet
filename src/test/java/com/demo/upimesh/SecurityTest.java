package com.demo.upimesh;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.domain.Device;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.PaymentInstruction;
import com.demo.upimesh.protocol.SignedEnvelope;
import com.demo.upimesh.service.IngestionService.IngestResult;
import com.demo.upimesh.service.IngestionService.Outcome;
import com.demo.upimesh.sim.OfflineVerifier;
import com.demo.upimesh.sim.PhoneClient;
import com.demo.upimesh.support.IntegrationTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityTest extends IntegrationTest {

    // ------------------------------------------------------------------ tampering

    @Test
    void tamperedCiphertextIsRejectedAndMovesNoMoney() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket p = alice.pay(bob, rs("100.00"), 5).packet();

        byte[] wire = Crypto.unb64(p.ciphertext());
        wire[wire.length - 20] ^= 0x01; // flip one bit inside the AES-GCM ciphertext
        MeshPacket tampered = new MeshPacket(p.packetId(), p.keyId(), p.ttl(), p.createdAt(), Crypto.b64(wire));

        IngestResult r = deliver(tampered, "bridge-1");

        assertThat(r.outcome()).isEqualTo(Outcome.REJECTED);
        assertThat(r.reason()).isEqualTo("decryption_failed");
        assertThat(balance(bob)).isEqualByComparingTo("0.00");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("1000.00");
        // the genuine packet still works afterwards
        assertThat(deliver(p, "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
    }

    @Test
    void rewritingTheOuterKeyIdBreaksDecryption() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket p = alice.pay(bob, rs("100.00"), 5).packet();

        IngestResult r = deliver(new MeshPacket(p.packetId(), "enc-doesnotexist", p.ttl(), p.createdAt(), p.ciphertext()), "bridge-1");

        assertThat(r.outcome()).isEqualTo(Outcome.REJECTED);
        assertThat(r.reason()).isEqualTo("unknown_or_expired_key");
    }

    // ------------------------------------------------------------------ authentication

    @Test
    void forgedSenderWithValidEncryptionButWrongSignatureIsRejected() {
        PhoneClient victim = onboardedPhone("Victim", "5000.00", "1000.00", "500.00");
        String mallory = newAccount("Mallory", "0.00");

        // Mallory knows the victim's public identifiers and the server's PUBLIC encryption key,
        // so she can produce a perfectly decryptable packet — but she can't sign as the victim.
        PaymentInstruction in = new PaymentInstruction(victim.vpa(), mallory, rs("500.00"), victim.deviceId(),
                victim.nextCounter(), UUID.randomUUID().toString(), clock.millis(), victim.wallet().certId());
        String malloryKeySig = Crypto.sign(Crypto.newEcKeyPair().getPrivate(), in.canonical());
        MeshPacket forged = victim.encryptEnvelope(new SignedEnvelope(in, malloryKeySig), 5);

        IngestResult r = deliver(forged, "bridge-1");

        assertThat(r.outcome()).isEqualTo(Outcome.REJECTED);
        assertThat(r.reason()).isEqualTo("bad_signature");
        assertThat(balance(mallory)).isEqualByComparingTo("0.00");
        assertThat(walletRemaining(victim)).isEqualByComparingTo("1000.00");
        // forging must not let an attacker get the victim's device flagged
        assertThat(devices.findById(victim.deviceId()).orElseThrow().getStatus()).isEqualTo(Device.Status.ACTIVE);
        // and the rejection still comes with a verifiable receipt
        assertThat(OfflineVerifier.checkReceipt(r.receipt(), serverSigningKeys())).isTrue();
    }

    @Test
    void someoneElsesDeviceCannotSpendFromYourWallet() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        PhoneClient eve = onboardedPhone("Eve", "5000.00", "100.00", "100.00");
        String bob = newAccount("Bob", "0.00");

        // Eve signs correctly with HER device, but points at Alice's wallet certificate.
        PaymentInstruction in = new PaymentInstruction(eve.vpa(), bob, rs("50.00"), eve.deviceId(),
                eve.nextCounter(), UUID.randomUUID().toString(), clock.millis(), alice.wallet().certId());
        MeshPacket p = eve.encryptEnvelope(new SignedEnvelope(in, Crypto.sign(eve.keys().getPrivate(), in.canonical())), 5);

        IngestResult r = deliver(p, "bridge-1");
        assertThat(r.reason()).isEqualTo("wallet_mismatch");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("1000.00");
    }

    @Test
    void revokedDeviceCannotPay() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket p = alice.pay(bob, rs("100.00"), 5).packet();

        onboarding.revokeDevice(alice.deviceId(), alice.vpa(), PIN);

        assertThat(deliver(p, "bridge-1").reason()).isEqualTo("device_revoked");
        assertThat(balance(bob)).isEqualByComparingTo("0.00");
    }

    // ------------------------------------------------------------------ replay / freshness

    @Test
    void stalePacketIsRejected() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        long fourDaysAgo = clock.instant().minus(Duration.ofHours(96)).toEpochMilli();
        MeshPacket old = alice.forge(bob, rs("100.00"), alice.nextCounter(), fourDaysAgo, 5).packet();

        IngestResult r = deliver(old, "bridge-1");
        assertThat(r.reason()).isEqualTo("stale_packet");
        assertThat(balance(bob)).isEqualByComparingTo("0.00");
    }

    @Test
    void futureDatedPacketIsRejected() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        long inOneHour = clock.instant().plus(Duration.ofHours(1)).toEpochMilli();

        IngestResult r = deliver(alice.forge(bob, rs("100.00"), alice.nextCounter(), inOneHour, 5).packet(), "bridge-1");
        assertThat(r.reason()).isEqualTo("future_dated");
    }

    @Test
    void reEncryptingTheSameSignedPaymentIsADuplicateNotNewMoney() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        PhoneClient.PaymentBundle b = alice.pay(bob, rs("100.00"), 5);
        // Same signed envelope, fresh hybrid encryption -> different ciphertext and packet hash.
        MeshPacket reEncrypted = alice.encryptEnvelope(b.iou().envelope(), 5);

        assertThat(deliver(b.packet(), "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
        IngestResult second = deliver(reEncrypted, "bridge-2");

        assertThat(second.outcome()).isEqualTo(Outcome.DUPLICATE);
        assertThat(balance(bob)).isEqualByComparingTo("100.00");
        assertThat(devices.findById(alice.deviceId()).orElseThrow().getStatus()).isEqualTo(Device.Status.ACTIVE);
    }

    @Test
    void sequentialCounterForkIsRejectedAndFlagsTheDevice() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        String carol = newAccount("Carol", "0.00");
        long n = alice.nextCounter();

        assertThat(deliver(alice.forge(bob, rs("100.00"), n, clock.millis(), 5).packet(), "bridge-1").outcome())
                .isEqualTo(Outcome.SETTLED);
        IngestResult fork = deliver(alice.forge(carol, rs("100.00"), n, clock.millis(), 5).packet(), "bridge-2");

        assertThat(fork.reason()).isEqualTo("counter_reused");
        assertThat(balance(carol)).isEqualByComparingTo("0.00");
        assertThat(devices.findById(alice.deviceId()).orElseThrow().getStatus()).isEqualTo(Device.Status.FLAGGED);
    }

    @Test
    void outOfOrderCountersAreFine() {
        // Mesh delivery order is random: counter 2 may arrive before counter 1.
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket first = alice.pay(bob, rs("10.00"), 5).packet();
        MeshPacket second = alice.pay(bob, rs("20.00"), 5).packet();

        assertThat(deliver(second, "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
        assertThat(deliver(first, "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
        assertThat(balance(bob)).isEqualByComparingTo("30.00");
    }

    // ------------------------------------------------------------------ limits

    @Test
    void overLimitOfflineSpendIsBlockedLocallyAndOnTheServer() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "500.00", "300.00");
        String bob = newAccount("Bob", "0.00");

        MeshPacket ok = alice.pay(bob, rs("300.00"), 5).packet();
        // the honest app refuses to overspend...
        assertThatThrownBy(() -> alice.pay(bob, rs("300.00"), 5))
                .isInstanceOf(PhoneClient.LocalLimitException.class);
        // ...a tampered app can sign it anyway, but the server reserve stops it
        MeshPacket over = alice.forge(bob, rs("300.00"), alice.nextCounter(), clock.millis(), 5).packet();

        assertThat(deliver(ok, "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
        IngestResult r = deliver(over, "bridge-1");
        assertThat(r.reason()).isEqualTo("offline_limit_exceeded");
        assertThat(balance(bob)).isEqualByComparingTo("300.00");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("200.00");
        // and the main balance was never touched beyond the original reservation
        assertThat(balance(alice.vpa())).isEqualByComparingTo("4500.00");
    }

    @Test
    void perTransactionCapIsEnforcedByTheServer() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "100.00");
        String bob = newAccount("Bob", "0.00");
        IngestResult r = deliver(alice.forge(bob, rs("150.00"), alice.nextCounter(), clock.millis(), 5).packet(), "bridge-1");
        assertThat(r.reason()).isEqualTo("over_per_txn_cap");
    }

    @Test
    void unknownReceiverIsRejectedWithoutTouchingTheWallet() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        IngestResult r = deliver(alice.pay("nobody-x@test", rs("50.00"), 5).packet(), "bridge-1");
        assertThat(r.reason()).isEqualTo("unknown_receiver");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("1000.00");
    }
}
