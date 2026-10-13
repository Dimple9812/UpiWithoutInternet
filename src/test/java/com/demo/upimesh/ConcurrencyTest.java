package com.demo.upimesh;

import com.demo.upimesh.domain.Device;
import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.service.IngestionService.IngestResult;
import com.demo.upimesh.service.IngestionService.Outcome;
import com.demo.upimesh.sim.PhoneClient;
import com.demo.upimesh.support.IntegrationTest;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

class ConcurrencyTest extends IntegrationTest {

    @Test
    void samePacketFromThreeBridgesAtOnceSettlesExactlyOnce() throws Exception {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "100.00");
        MeshPacket packet = alice.pay(bob, rs("250.00"), 5).packet();

        List<IngestResult> results = race(3, i -> () -> deliver(packet, "bridge-" + (i + 1)));

        assertThat(results).extracting(IngestResult::outcome)
                .containsExactlyInAnyOrder(Outcome.SETTLED, Outcome.DUPLICATE, Outcome.DUPLICATE);
        assertThat(balance(bob)).isEqualByComparingTo("350.00");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("750.00");
        assertThat(payments.findByPacketHash(results.get(0).packetHash())).isPresent();
    }

    @Test
    void duplicateStormOfTwentyUploadsStillSettlesOnce() throws Exception {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        MeshPacket packet = alice.pay(bob, rs("10.00"), 5).packet();

        List<IngestResult> results = race(20, i -> () -> deliver(packet, "bridge-" + (i % 3 + 1)));

        assertThat(results.stream().filter(r -> r.outcome() == Outcome.SETTLED)).hasSize(1);
        assertThat(results.stream().filter(r -> r.outcome() == Outcome.DUPLICATE)).hasSize(19);
        assertThat(balance(bob)).isEqualByComparingTo("10.00");
    }

    @Test
    void twoDifferentPaymentsWithTheSameCounterRacingSettleOnlyOne() throws Exception {
        // A cloned wallet: two genuinely signed payments that reuse counter N.
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        String bob = newAccount("Bob", "0.00");
        String carol = newAccount("Carol", "0.00");
        long counter = alice.wallet().counterStart();
        MeshPacket toBob = alice.forge(bob, rs("300.00"), counter, clock.millis(), 5).packet();
        MeshPacket toCarol = alice.forge(carol, rs("300.00"), counter, clock.millis(), 5).packet();

        List<IngestResult> results = race(2, i -> () -> deliver(i == 0 ? toBob : toCarol, "bridge-1"));

        assertThat(results).extracting(IngestResult::outcome)
                .containsExactlyInAnyOrder(Outcome.SETTLED, Outcome.REJECTED);
        assertThat(results).filteredOn(r -> r.outcome() == Outcome.REJECTED)
                .extracting(IngestResult::reason).containsExactly("counter_reused");
        assertThat(balance(bob).add(balance(carol))).isEqualByComparingTo("300.00");
        assertThat(walletRemaining(alice)).isEqualByComparingTo("700.00");
        assertThat(devices.findById(alice.deviceId()).orElseThrow().getStatus()).isEqualTo(Device.Status.FLAGGED);
    }

    /** Runs n tasks released at the same instant and returns their results. */
    private static List<IngestResult> race(int n, java.util.function.IntFunction<Supplier<IngestResult>> task)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<IngestResult>> fs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Supplier<IngestResult> s = task.apply(i);
            fs.add(pool.submit(() -> { go.await(); return s.get(); }));
        }
        go.countDown();
        List<IngestResult> out = new ArrayList<>();
        for (Future<IngestResult> f : fs) out.add(f.get(30, TimeUnit.SECONDS));
        pool.shutdown();
        return out;
    }
}
