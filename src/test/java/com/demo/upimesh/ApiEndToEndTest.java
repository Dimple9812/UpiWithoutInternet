package com.demo.upimesh;

import com.demo.upimesh.protocol.MeshPacket;
import com.demo.upimesh.protocol.SettlementReceipt;
import com.demo.upimesh.protocol.WalletCertificate;
import com.demo.upimesh.sim.OfflineVerifier;
import com.demo.upimesh.sim.PhoneClient;
import com.demo.upimesh.support.IntegrationTest;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** The whole protocol over HTTP, exactly as a phone and a bridge would call it. */
class ApiEndToEndTest extends IntegrationTest {

    private static final String BRIDGE_TOKEN = "test-token-bridge-one-0123456789";

    @Autowired TestRestTemplate http;

    @Test
    void onboardPayOfflineRelayAndSettle() {
        String alice = newAccount("Alice", "3000.00");
        String bob = newAccount("Bob", "50.00");

        // ---- ONLINE: phone fetches keys, registers its device key, loads an offline wallet
        JsonNode keys = http.getForObject("/api/v1/keys", JsonNode.class);
        PhoneClient phone = new PhoneClient(alice, "dev-" + UUID.randomUUID().toString().substring(0, 8), clock);
        phone.installServerKey(keys.at("/encryption/keyId").asText(), keys.at("/encryption/publicKey").asText());

        ResponseEntity<JsonNode> reg = http.postForEntity("/api/v1/devices", Map.of(
                "vpa", alice, "deviceId", phone.deviceId(), "publicKey", phone.publicKeyB64(), "pin", PIN), JsonNode.class);
        assertThat(reg.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<WalletCertificate> load = http.postForEntity("/api/v1/wallets", Map.of(
                "vpa", alice, "deviceId", phone.deviceId(), "amount", "1000.00", "perTxnCap", "400.00", "pin", PIN),
                WalletCertificate.class);
        assertThat(load.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        phone.installWallet(load.getBody());
        assertThat(balance(alice)).isEqualByComparingTo("2000.00"); // reserved out of the main balance

        // ---- OFFLINE: pay Bob; Bob checks the IOU with no internet
        PhoneClient.PaymentBundle b = phone.pay(bob, rs("350.00"), 5);
        assertThat(OfflineVerifier.checkIou(b.iou(), bob, serverSigningKeys(), clock.millis())).isEmpty();
        assertThat(OfflineVerifier.checkIou(b.iou(), "someone-else@test", serverSigningKeys(), clock.millis()))
                .contains("not_for_me");

        // ---- BRIDGE: a stranger's phone gets 4G and uploads
        ResponseEntity<JsonNode> up = ingest(b.packet().hop().hop(), BRIDGE_TOKEN, 2);
        assertThat(up.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(up.getBody().get("outcome").asText()).isEqualTo("SETTLED");
        String hash = up.getBody().get("packetHash").asText();

        // ---- RECEIPT: signed by the server, verifiable offline, fetchable later
        SettlementReceipt receipt = http.getForObject("/api/v1/receipts/" + hash, SettlementReceipt.class);
        assertThat(receipt.status()).isEqualTo("SETTLED");
        assertThat(OfflineVerifier.checkReceipt(receipt, serverSigningKeys())).isTrue();
        assertThat(payments.findByPacketHash(hash).orElseThrow().getBridgeNodeId()).isEqualTo("bridge-1");
        assertThat(balance(bob)).isEqualByComparingTo("400.00");

        // ---- second bridge uploads the same packet
        assertThat(ingest(b.packet(), "test-token-bridge-two-0123456789", 1).getBody().get("outcome").asText())
                .isEqualTo("DUPLICATE");
    }

    @Test
    void bridgeEndpointRequiresAValidToken() {
        PhoneClient alice = onboardedPhone("Alice", "5000.00", "1000.00", "500.00");
        MeshPacket p = alice.pay(newAccount("Bob", "0.00"), rs("10.00"), 5).packet();

        assertThat(ingest(p, null, 0).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ingest(p, "not-a-real-token-at-all-000000", 0).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ingest(p, BRIDGE_TOKEN, 0).getStatusCode()).isEqualTo(HttpStatus.OK);
        // auth runs before body validation: anonymous junk gets 401, not a format hint
        assertThat(http.postForEntity("/api/v1/bridge/ingest", new HttpEntity<>(Map.of(), headers(null, 0)),
                JsonNode.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void malformedPacketsAreRejectedWith400() {
        HttpHeaders h = headers(BRIDGE_TOKEN, 0);
        ResponseEntity<JsonNode> missing = http.postForEntity("/api/v1/bridge/ingest",
                new HttpEntity<>(Map.of("packetId", "abc12345"), h), JsonNode.class);
        assertThat(missing.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<JsonNode> notBase64 = http.postForEntity("/api/v1/bridge/ingest", new HttpEntity<>(Map.of(
                "packetId", "abc12345", "keyId", "enc-1234", "ttl", 3, "createdAt", 1, "ciphertext", "%%%"), h), JsonNode.class);
        assertThat(notBase64.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(notBase64.getBody().get("error").asText()).isEqualTo("bad_ciphertext");
    }

    @Test
    void onboardingRejectsWrongPinAndNonP256Keys() {
        String alice = newAccount("Alice", "1000.00");
        PhoneClient phone = new PhoneClient(alice, "dev-" + UUID.randomUUID().toString().substring(0, 8), clock);

        ResponseEntity<JsonNode> wrongPin = http.postForEntity("/api/v1/devices", Map.of(
                "vpa", alice, "deviceId", phone.deviceId(), "publicKey", phone.publicKeyB64(), "pin", "0000"), JsonNode.class);
        assertThat(wrongPin.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        String rsaKey = vault.activeKey(com.demo.upimesh.keys.KeyVault.Purpose.ENCRYPTION).publicKey();
        ResponseEntity<JsonNode> badKey = http.postForEntity("/api/v1/devices", Map.of(
                "vpa", alice, "deviceId", phone.deviceId(), "publicKey", rsaKey, "pin", PIN), JsonNode.class);
        assertThat(badKey.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void cannotReserveMoreThanTheBalanceOrHaveTwoActiveWallets() {
        PhoneClient alice = onboardedPhone("Alice", "1500.00", "1000.00", "500.00");

        ResponseEntity<JsonNode> second = http.postForEntity("/api/v1/wallets", Map.of(
                "vpa", alice.vpa(), "deviceId", alice.deviceId(), "amount", "100.00", "pin", PIN), JsonNode.class);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        String poor = newAccount("Poor", "10.00");
        PhoneClient p2 = new PhoneClient(poor, "dev-" + UUID.randomUUID().toString().substring(0, 8), clock);
        onboarding.registerDevice(poor, p2.deviceId(), p2.publicKeyB64(), PIN);
        ResponseEntity<JsonNode> tooMuch = http.postForEntity("/api/v1/wallets", Map.of(
                "vpa", poor, "deviceId", p2.deviceId(), "amount", "100.00", "pin", PIN), JsonNode.class);
        assertThat(tooMuch.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @Test
    void demoEndpointsDoNotExistOutsideTheDemoProfile() {
        assertThat(http.getForEntity("/api/accounts", String.class).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(http.postForEntity("/api/demo/send", Map.of(), String.class).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    private ResponseEntity<JsonNode> ingest(MeshPacket p, String token, int hops) {
        return http.postForEntity("/api/v1/bridge/ingest", new HttpEntity<>(p, headers(token, hops)), JsonNode.class);
    }

    private static HttpHeaders headers(String token, int hops) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) h.setBearerAuth(token);
        h.set("X-Hop-Count", Integer.toString(hops));
        return h;
    }
}
