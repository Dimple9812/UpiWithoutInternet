package com.demo.upimesh.idempotency;

import com.demo.upimesh.config.MeshPayProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Redis implementation. The claim is a single Lua script so "check state, then set
 * PROCESSING" is atomic across every server instance (plain SET NX cannot express
 * "absent OR RETRYABLE").
 */
@Component
@ConditionalOnProperty(name = "meshpay.idempotency.store", havingValue = "redis", matchIfMissing = true)
public class RedisIdempotencyStore implements IdempotencyStore {

    private static final String PREFIX = "meshpay:idem:";

    private static final DefaultRedisScript<String> CLAIM = new DefaultRedisScript<>("""
            local v = redis.call('GET', KEYS[1])
            if (not v) or v == 'RETRYABLE' then
              redis.call('SET', KEYS[1], 'PROCESSING', 'EX', ARGV[1])
              return 'ACQUIRED'
            end
            return v
            """, String.class);

    private final StringRedisTemplate redis;
    private final MeshPayProperties.Idempotency cfg;

    public RedisIdempotencyStore(StringRedisTemplate redis, MeshPayProperties props) {
        this.redis = redis;
        this.cfg = props.idempotency();
    }

    @Override
    public Claim claim(String packetHash) {
        String r = redis.execute(CLAIM, List.of(PREFIX + packetHash),
                Long.toString(cfg.processingLease().toSeconds()));
        if ("ACQUIRED".equals(r)) return new Claim(true, State.PROCESSING);
        return new Claim(false, State.valueOf(r));
    }

    @Override
    public void complete(String packetHash, State finalState) {
        redis.opsForValue().set(PREFIX + packetHash, finalState.name(), cfg.finalStateTtl());
    }

    @Override
    public void releaseForRetry(String packetHash) {
        redis.opsForValue().set(PREFIX + packetHash, State.RETRYABLE.name(), cfg.finalStateTtl());
    }

    @Override
    public Optional<State> get(String packetHash) {
        return Optional.ofNullable(redis.opsForValue().get(PREFIX + packetHash)).map(State::valueOf);
    }

    @Override
    public long size() {
        return keys().size();
    }

    @Override
    public void clearAll() {
        List<String> keys = keys();
        if (!keys.isEmpty()) redis.delete(keys);
    }

    private List<String> keys() {
        List<String> out = new ArrayList<>();
        try (Cursor<String> c = redis.scan(ScanOptions.scanOptions().match(PREFIX + "*").count(500).build())) {
            c.forEachRemaining(out::add);
        }
        return out;
    }
}
