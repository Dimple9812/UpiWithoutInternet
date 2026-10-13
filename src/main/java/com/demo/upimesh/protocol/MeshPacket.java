package com.demo.upimesh.protocol;

import jakarta.validation.constraints.*;

/**
 * What hops between phones. Relays can read the outer fields (needed for routing,
 * dedup and expiry) but not the ciphertext.
 *
 * Outer fields are NOT trusted by the server: {@code packetId}, {@code ttl} and
 * {@code createdAt} only steer gossip. The server's idempotency key is the hash of
 * the ciphertext, and {@code keyId} is bound into the AES-GCM AAD.
 */
public record MeshPacket(
        @NotBlank @Pattern(regexp = "^[A-Za-z0-9-]{8,64}$") String packetId,
        @NotBlank @Pattern(regexp = "^[A-Za-z0-9_-]{4,64}$") String keyId,
        @Min(0) @Max(32) int ttl,
        @Positive long createdAt,
        @NotBlank @Size(max = 16384) String ciphertext) {

    public MeshPacket hop() {
        return new MeshPacket(packetId, keyId, Math.max(0, ttl - 1), createdAt, ciphertext);
    }
}
