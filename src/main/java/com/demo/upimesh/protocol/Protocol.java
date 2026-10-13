package com.demo.upimesh.protocol;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Field formats shared by every message in the protocol.
 *
 * Signatures are computed over a canonical newline-separated string (see the
 * {@code canonical()} method on each message). The formats below guarantee no
 * field can contain a newline, so two different messages can never produce the
 * same canonical string.
 */
public final class Protocol {

    public static final Pattern VPA = Pattern.compile("^[a-zA-Z0-9._-]{2,64}@[a-zA-Z0-9]{2,32}$");
    public static final Pattern DEVICE_ID = Pattern.compile("^[A-Za-z0-9_-]{3,64}$");
    public static final Pattern NONCE = Pattern.compile("^[A-Za-z0-9-]{16,64}$");
    public static final Pattern UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    public static final Pattern KEY_ID = Pattern.compile("^[A-Za-z0-9_-]{4,64}$");

    private Protocol() {}

    /** Amounts are rupees with at most 2 decimals, always serialised as e.g. "100.00". */
    public static String fmtAmount(BigDecimal a) {
        Objects.requireNonNull(a, "amount");
        return a.setScale(2, RoundingMode.UNNECESSARY).toPlainString();
    }

    public static boolean validAmount(BigDecimal a) {
        return a != null && a.signum() > 0 && a.stripTrailingZeros().scale() <= 2
                && a.compareTo(new BigDecimal("10000000")) < 0;
    }

    public static String nz(Object o) { return o == null ? "" : o.toString(); }

    public static boolean matches(Pattern p, String s) { return s != null && p.matcher(s).matches(); }
}
