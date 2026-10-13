package com.demo.upimesh.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.Map;

@ConfigurationProperties(prefix = "meshpay")
public record MeshPayProperties(
        /* A packet signed longer ago than this is rejected as stale. */
        @DefaultValue("72h") Duration packetMaxAge,
        /* Tolerance for phone clocks running ahead of the server. */
        @DefaultValue("5m") Duration clockSkew,
        @DefaultValue Idempotency idempotency,
        @DefaultValue Wallet wallet,
        @DefaultValue Bridge bridge,
        @DefaultValue Keys keys) {

    public record Idempotency(
            /* "redis" (default, multi-instance safe) or "memory" (single instance, tests/demo). */
            @DefaultValue("redis") String store,
            /* How long a PROCESSING claim lives if the server dies mid-request. */
            @DefaultValue("60s") Duration processingLease,
            /* How long final states (SETTLED/REJECTED) are remembered. The DB is the backstop after that. */
            @DefaultValue("10d") Duration finalStateTtl) {}

    public record Wallet(
            @DefaultValue("2000.00") BigDecimal maxLimit,
            @DefaultValue("500.00") BigDecimal maxPerTxn,
            @DefaultValue("7d") Duration validity) {}

    public record Bridge(
            /* bridgeId -> bearer token. The bridge identity comes from the token, never a header. */
            Map<String, String> tokens,
            @DefaultValue("120") int rateLimitCapacity,
            @DefaultValue("20") int rateLimitRefillPerSecond) {

        public Map<String, String> tokens() { return tokens == null ? Map.of() : tokens; }
    }

    public record Keys(
            /* Base64 32-byte key that wraps server private keys at rest (stand-in for a KMS). */
            String masterKey,
            @DefaultValue("2048") int rsaBits,
            /* Retired encryption keys still decrypt for this long, so in-flight packets survive rotation. */
            @DefaultValue("8d") Duration retiredKeyGrace) {}
}
