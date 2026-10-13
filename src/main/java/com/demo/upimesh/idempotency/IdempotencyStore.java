package com.demo.upimesh.idempotency;

import java.util.Optional;

/**
 * First line of defence against the same packet arriving from many bridges.
 * Keyed by SHA-256 of the ciphertext bytes.
 *
 * <pre>
 *            claim()                complete()
 *  (absent) ─────────▶ PROCESSING ─────────────▶ SETTLED / REJECTED   (final, long TTL)
 *      ▲                   │ releaseForRetry()
 *      │                   ▼
 *      └──── claim() ── RETRYABLE   (transient failure: the next copy may try again)
 *
 *  PROCESSING has a short lease: if the server dies mid-request the key expires and
 *  the packet can be retried. The DB unique constraints make that retry safe.
 * </pre>
 *
 * This store is an optimisation, not the source of truth: if it is wiped (Redis
 * restart, eviction), the database constraints still prevent any double settlement.
 */
public interface IdempotencyStore {

    enum State { PROCESSING, SETTLED, REJECTED, RETRYABLE }

    /** @param acquired true if this caller now owns the packet; otherwise {@code current} says why not. */
    record Claim(boolean acquired, State current) {}

    Claim claim(String packetHash);

    void complete(String packetHash, State finalState);

    void releaseForRetry(String packetHash);

    Optional<State> get(String packetHash);

    long size();

    void clearAll();
}
