package com.demo.upimesh.idempotency;

import com.demo.upimesh.config.MeshPayProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Single-instance fallback with the same semantics as the Redis store. */
@Component
@ConditionalOnProperty(name = "meshpay.idempotency.store", havingValue = "memory")
public class InMemoryIdempotencyStore implements IdempotencyStore {

    private record Entry(State state, Instant expiresAt) {}

    private final ConcurrentHashMap<String, Entry> map = new ConcurrentHashMap<>();
    private final MeshPayProperties.Idempotency cfg;
    private final Clock clock;

    public InMemoryIdempotencyStore(MeshPayProperties props, Clock clock) {
        this.cfg = props.idempotency();
        this.clock = clock;
    }

    @Override
    public Claim claim(String packetHash) {
        Instant now = clock.instant();
        boolean[] acquired = {false};
        Entry e = map.compute(packetHash, (k, cur) -> {
            if (cur == null || cur.expiresAt.isBefore(now) || cur.state == State.RETRYABLE) {
                acquired[0] = true;
                return new Entry(State.PROCESSING, now.plus(cfg.processingLease()));
            }
            return cur;
        });
        return new Claim(acquired[0], e.state);
    }

    @Override
    public void complete(String packetHash, State finalState) {
        put(packetHash, finalState, cfg.finalStateTtl());
    }

    @Override
    public void releaseForRetry(String packetHash) {
        put(packetHash, State.RETRYABLE, cfg.finalStateTtl());
    }

    @Override
    public Optional<State> get(String packetHash) {
        Entry e = map.get(packetHash);
        return e == null || e.expiresAt.isBefore(clock.instant()) ? Optional.empty() : Optional.of(e.state);
    }

    @Override
    public long size() { return map.size(); }

    @Override
    public void clearAll() { map.clear(); }

    @Scheduled(fixedDelay = 60_000)
    void evict() {
        Instant now = clock.instant();
        map.entrySet().removeIf(e -> e.getValue().expiresAt.isBefore(now));
    }

    private void put(String k, State s, Duration ttl) {
        map.put(k, new Entry(s, clock.instant().plus(ttl)));
    }
}
