package com.demo.upimesh.demo;

import com.demo.upimesh.support.IntegrationTest;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The simulator page's flows, end to end: real phones, real packets, the real
 * ingestion pipeline. Phones are moved into 4G directly so results are deterministic.
 */
@ActiveProfiles({"demo", "test"})
// Same DB as the other test contexts, so it must unwrap the same server keys.
@TestPropertySource(properties = "meshpay.keys.master-key=dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLWV4YWN0bHk=")
class SimulatorTest extends IntegrationTest {

    @Autowired TestRestTemplate http;
    @Autowired SimService sim;

    @BeforeEach
    void freshMesh() { sim.reset(); }

    @Test
    void offlinePaymentRelaysSettlesAndTheReceiverLearnsFromTheMesh() {
        BigDecimal bobBefore = balance("bob@demo");
        JsonNode sent = http.postForObject("/api/sim/pay",
                Map.of("from", "alice@demo", "to", "bob@demo", "amount", 42), JsonNode.class);
        assertThat(sent.get("iouCheck").asText()).isEqualTo("valid"); // Bob verified it offline

        // Alice -> Ravi (relay) -> Ravi walks into 4G; Bob waits next to Alice.
        sim.engine().place("alice", 40, 30, 100);
        sim.engine().place("ravi", 50, 30, 100);
        sim.engine().place("bob", 35, 30, 100);
        parkEveryoneElse("alice", "ravi", "bob");
        sim.step(1);
        sim.engine().place("ravi", 90, 30, 100);
        sim.step(1);
        assertThat(balance("bob@demo")).isEqualByComparingTo(bobBefore.add(new BigDecimal("42")));

        sim.engine().place("ravi", 45, 30, 100); // Ravi comes back with the receipt
        sim.step(1);
        SimService.PaymentView v = view(sent.get("hash").asText());
        assertThat(v.serverStatus).isEqualTo("SETTLED");
        assertThat(v.receiverStatus).isEqualTo("SETTLED");
        assertThat(v.receiverKnewTick).isNotNull();
        assertThat(sim.engine().copiesInMesh(v.hash)).isZero(); // every copy dropped after the receipt
    }

    @Test
    void everyAttackIsStoppedByTheRealPipeline() {
        // something settled first, so there is a payment to replay
        http.postForObject("/api/sim/pay", Map.of("from", "carol@demo", "to", "dave@demo", "amount", 10), JsonNode.class);
        deliverEverything();

        List<SimService.PaymentView> tamper = attack("tamper");
        List<SimService.PaymentView> forge = attack("forge");
        List<SimService.PaymentView> clone = attack("clone");
        List<SimService.PaymentView> over = attack("overspend");
        deliverEverything();
        List<SimService.PaymentView> replay = attack("replay");
        deliverEverything();

        assertThat(statusOf(tamper.get(0))).isEqualTo("SETTLED");
        assertThat(statusOf(tamper.get(1))).isEqualTo("REJECTED:decryption_failed");
        assertThat(statusOf(forge.get(0))).isEqualTo("REJECTED:bad_signature");
        assertThat(forge.get(0).iouCheck).isEqualTo("fails: bad_signature"); // receiver would catch it offline too
        assertThat(List.of(statusOf(clone.get(0)), statusOf(clone.get(1))))
                .containsExactlyInAnyOrder("SETTLED", "REJECTED:counter_reused");
        assertThat(over.stream().map(this::statusOf)).contains("SETTLED", "REJECTED:offline_limit_exceeded");
        assertThat(statusOf(replay.get(0))).startsWith("DUPLICATE");
        assertThat(devices.findAll().stream().filter(d -> d.getVpa().equals("alice@demo"))
                .anyMatch(d -> d.getStatus() == com.demo.upimesh.domain.Device.Status.FLAGGED)).isTrue();
    }

    @Test
    void phoneRefusesToOverspendAndStateRendersForThePage() {
        var r = http.postForEntity("/api/sim/pay", Map.of("from", "dave@demo", "to", "bob@demo", "amount", 100000), JsonNode.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(r.getBody().get("message").asText()).contains("Phone refused");

        JsonNode state = http.getForObject("/api/sim/state", JsonNode.class);
        assertThat(state.get("nodes")).hasSize(11);
        assertThat(state.get("people")).hasSize(4);
        assertThat(http.getForEntity("/", String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // ------------------------------------------------------------------ helpers

    private List<SimService.PaymentView> attack(String kind) {
        SimService.PaymentView[] out = http.postForObject("/api/sim/attack/" + kind, null, SimService.PaymentView[].class);
        return List.of(out);
    }

    /** Teleport every phone into 4G with a full battery so everything carried gets uploaded. */
    private void deliverEverything() {
        int y = 2;
        for (var n : sim.engine().nodes()) { sim.engine().place(n.id(), 92, y, 100); y += 5; }
        sim.step(3);
    }

    private void parkEveryoneElse(String... keep) {
        List<String> k = List.of(keep);
        int y = 2;
        for (var n : sim.engine().nodes()) {
            if (!k.contains(n.id())) { sim.engine().place(n.id(), 2, y, 100); y += 5; }
        }
    }

    private SimService.PaymentView view(String hash) {
        return sim.viewsForTest().stream().filter(v -> v.hash.equals(hash)).findFirst().orElseThrow();
    }

    private String statusOf(SimService.PaymentView fromResponse) {
        SimService.PaymentView v = sim.viewsForTest().stream()
                .filter(x -> x.packetId.equals(fromResponse.packetId)).findFirst().orElseThrow();
        return v.reason == null ? v.serverStatus : v.serverStatus + ":" + v.reason;
    }
}
