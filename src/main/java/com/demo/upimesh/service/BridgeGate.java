package com.demo.upimesh.service;

import com.demo.upimesh.config.MeshPayProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authenticates bridge uploads and rate-limits them per bridge.
 *
 * The bridge's identity comes from its bearer token (configured as
 * {@code meshpay.bridge.tokens.<bridgeId>=<token>}); headers cannot claim to be a
 * different bridge. Rate limiting is a per-bridge token bucket kept in memory —
 * per instance, which is fine for a prototype; use a Redis-backed limiter or the
 * API gateway's limiter when running several instances.
 */
@Component
public class BridgeGate {

    private final Map<String, byte[]> tokens; // bridgeId -> token bytes
    private final MeshPayProperties.Bridge cfg;
    private final Clock clock;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public BridgeGate(MeshPayProperties props, Clock clock) {
        this.cfg = props.bridge();
        this.clock = clock;
        this.tokens = new ConcurrentHashMap<>();
        cfg.tokens().forEach((id, tok) -> {
            if (tok != null && tok.length() >= 16) tokens.put(id, tok.getBytes(StandardCharsets.UTF_8));
        });
    }

    /** @return the authenticated bridgeId */
    public String authenticate(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw ApiException.unauthorized("missing_bridge_token", "Authorization: Bearer <bridge token> required");
        }
        byte[] presented = authorizationHeader.substring(7).trim().getBytes(StandardCharsets.UTF_8);
        String match = null;
        for (Map.Entry<String, byte[]> e : tokens.entrySet()) {
            // constant-time compare, and keep looping so timing doesn't reveal which entry matched
            if (MessageDigest.isEqual(e.getValue(), presented)) match = e.getKey();
        }
        if (match == null) throw ApiException.unauthorized("bad_bridge_token", "unknown bridge token");
        return match;
    }

    public void checkRate(String bridgeId) {
        Bucket b = buckets.computeIfAbsent(bridgeId, k -> new Bucket(cfg.rateLimitCapacity(), clock.millis()));
        if (!b.tryTake(cfg.rateLimitCapacity(), cfg.rateLimitRefillPerSecond(), clock.millis())) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "rate_limited", "slow down; retry later");
        }
    }

    private static final class Bucket {
        private double tokens;
        private long last;

        Bucket(int capacity, long now) { this.tokens = capacity; this.last = now; }

        synchronized boolean tryTake(int capacity, int refillPerSec, long now) {
            tokens = Math.min(capacity, tokens + (now - last) * refillPerSec / 1000.0);
            last = now;
            if (tokens < 1) return false;
            tokens -= 1;
            return true;
        }
    }
}
