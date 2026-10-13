package com.demo.upimesh.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

/** Real time plus an adjustable offset, so tests can jump days ahead. */
public class MutableClock extends Clock {

    private final AtomicReference<Duration> offset = new AtomicReference<>(Duration.ZERO);

    public void advance(Duration d) { offset.updateAndGet(o -> o.plus(d)); }

    public void reset() { offset.set(Duration.ZERO); }

    @Override public ZoneId getZone() { return ZoneOffset.UTC; }

    @Override public Clock withZone(ZoneId zone) { return this; }

    @Override public Instant instant() { return Instant.now().plus(offset.get()); }
}
