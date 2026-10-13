package com.demo.upimesh;

import com.demo.upimesh.domain.OfflineWallet;
import com.demo.upimesh.idempotency.IdempotencyStore;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.WalletCertificate;
import com.demo.upimesh.service.IngestionService.IngestResult;
import com.demo.upimesh.service.IngestionService.Outcome;
import com.demo.upimesh.sim.OfflineVerifier;
import com.demo.upimesh.sim.PhoneClient;
import com.demo.upimesh.support.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class ResilienceTest extends IntegrationTest {

    @Autowired DataSource dataSource;

    @Test
    void replayAfterServerRestartIsCaughtByTheDatabaseBackstop() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket p = alice.pay(bob, rs("200.00"), 5).packet();
        IngestResult first = deliver(p, "bridge-1");
        assertThat(first.outcome()).isEqualTo(Outcome.SETTLED);

        simulateRestart(); // Redis wiped, key caches dropped

        IngestResult replay = deliver(p, "bridge-2");
        assertThat(replay.outcome()).isEqualTo(Outcome.DUPLICATE);
        assertThat(replay.receipt()).isEqualTo(first.receipt());
        assertThat(balance(bob)).isEqualByComparingTo("200.00");
    }

    @Test
    void packetStillInTheMeshDuringARestartSettlesAfterwards() {
        // The original demo generated a new RSA key on every boot, stranding these packets.
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket inFlight = alice.pay(bob, rs("75.00"), 5).packet();

        simulateRestart();

        assertThat(deliver(inFlight, "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
        assertThat(balance(bob)).isEqualByComparingTo("75.00");
    }

    @Test
    void transientDatabaseFailureReturnsRetryThenTheSamePacketSettles() throws Exception {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket p = alice.pay(bob, rs("120.00"), 5).packet();

        IngestResult failed;
        // Another transaction holds the wallet row lock -> our settlement hits lock_timeout.
        try (Connection c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (PreparedStatement ps = c.prepareStatement("select 1 from offline_wallets where cert_id = ? for update")) {
                ps.setString(1, alice.wallet().certId());
                ps.executeQuery();
            }
            failed = deliver(p, "bridge-1");
            c.rollback();
        }

        assertThat(failed.outcome()).isEqualTo(Outcome.RETRY);
        assertThat(idempotency.get(failed.packetHash())).contains(IdempotencyStore.State.RETRYABLE);
        assertThat(balance(bob)).isEqualByComparingTo("0.00");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("1000.00");

        IngestResult retried = deliver(p, "bridge-2");
        assertThat(retried.outcome()).isEqualTo(Outcome.SETTLED);
        assertThat(balance(bob)).isEqualByComparingTo("120.00");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("880.00");
    }

    @Test
    void encryptionKeyRotationKeepsInFlightPacketsValidDuringTheGracePeriod() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket beforeRotation = alice.pay(bob, rs("10.00"), 5).packet();
        MeshPacket alsoBefore = alice.pay(bob, rs("10.00"), 5).packet();

        KeyVault.PublicKeyInfo fresh = vault.rotate(KeyVault.Purpose.ENCRYPTION);
        assertThat(fresh.keyId()).isNotEqualTo(beforeRotation.keyId());

        assertThat(deliver(beforeRotation, "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);

        clock.advance(Duration.ofDays(9)); // beyond the 8-day retired-key grace
        assertThat(deliver(alsoBefore, "bridge-1").reason()).isEqualTo("unknown_or_expired_key");
    }

    @Test
    void signingKeyRotationKeepsOldCertificatesAndReceiptsVerifiable() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        IngestResult before = deliver(alice.pay(bob, rs("10.00"), 5).packet(), "bridge-1");

        vault.rotate(KeyVault.Purpose.SIGNING);
        IngestResult after = deliver(alice.pay(bob, rs("10.00"), 5).packet(), "bridge-1");

        assertThat(after.receipt().signingKeyId()).isNotEqualTo(before.receipt().signingKeyId());
        assertThat(OfflineVerifier.checkReceipt(before.receipt(), serverSigningKeys())).isTrue();
        assertThat(OfflineVerifier.checkReceipt(after.receipt(), serverSigningKeys())).isTrue();
        assertThat(after.outcome()).isEqualTo(Outcome.SETTLED); // old certificate still accepted
    }

    @Test
    void expiredWalletIsClosedRefundedAndNoLongerSpendable() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        assertThat(deliver(alice.pay(bob, rs("100.00"), 5).packet(), "bridge-1").outcome()).isEqualTo(Outcome.SETTLED);
        assertThat(balance(alice.vpa())).isEqualByComparingTo("4000.00");

        // signed after the certificate expired: a tampered app could still try
        clock.advance(Duration.ofDays(7).plusHours(1));
        IngestResult late = deliver(alice.forge(bob, rs("50.00"), alice.nextCounter(), clock.millis(), 5).packet(), "bridge-1");
        assertThat(late.reason()).isEqualTo("wallet_expired");

        // after expiry + max packet age, the sweeper refunds what was left
        clock.advance(Duration.ofHours(72));
        onboarding.closeExpiredWallets();
        OfflineWallet w = wallets.findById(alice.wallet().certId()).orElseThrow();
        assertThat(w.getStatus()).isEqualTo(OfflineWallet.Status.CLOSED);
        assertThat(w.getRefunded()).isEqualByComparingTo("900.00");
        assertThat(balance(alice.vpa())).isEqualByComparingTo("4900.00");

        // a new wallet continues the device counter instead of restarting it
        WalletCertificate next = onboarding.issueWallet(alice.vpa(), alice.deviceId(), rs("200.00"), null, PIN);
        assertThat(next.counterStart()).isGreaterThan(alice.wallet().counterStart());
    }

    private void simulateRestart() {
        idempotency.clearAll();
        vault.reload();
    }
}
