package com.demo.upimesh;

import com.demo.upimesh.support.IntegrationTest;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.math.BigDecimal;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The dashboard's demo flow runs on the real protocol (device keys, wallets, signatures). */
@ActiveProfiles({"demo", "test"})
// Same DB as the other test contexts, so it must unwrap the same server keys.
@TestPropertySource(properties = "meshpay.keys.master-key=dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLWV4YWN0bHk=")
class DemoProfileTest extends IntegrationTest {

    @Autowired TestRestTemplate http;

    @Test
    void sendGossipFlushSettlesThroughTheFullPipeline() {
        http.postForObject("/api/mesh/reset", null, JsonNode.class);
        BigDecimal bobBefore = balance("bob@demo");

        JsonNode sent = http.postForObject("/api/demo/send", Map.of(
                "senderVpa", "carol@demo", "receiverVpa", "bob@demo", "amount", 42, "pin", "1234"), JsonNode.class);
        assertThat(sent.has("packetId")).as(sent.toString()).isTrue();
        assertThat(sent.get("offlineRemaining").decimalValue()).isEqualByComparingTo("958.00");

        http.postForObject("/api/mesh/gossip", null, JsonNode.class);
        JsonNode flushed = http.postForObject("/api/mesh/flush", null, JsonNode.class);

        assertThat(flushed.get("results").get(0).get("outcome").asText()).isEqualTo("SETTLED");
        assertThat(balance("bob@demo")).isEqualByComparingTo(bobBefore.add(new BigDecimal("42")));
        assertThat(http.getForEntity("/", String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
