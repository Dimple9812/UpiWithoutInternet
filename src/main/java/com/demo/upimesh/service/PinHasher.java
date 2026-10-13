package com.demo.upimesh.service;

import com.demo.upimesh.crypto.Crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.regex.Pattern;

/**
 * PBKDF2 PIN hashing. The PIN stands in for real bank authentication during the
 * ONLINE onboarding steps; it is never put inside mesh packets.
 */
public final class PinHasher {

    private static final Pattern PIN = Pattern.compile("^[0-9]{4,6}$");
    private static final int ITERATIONS = 120_000;

    private PinHasher() {}

    public record Hashed(String salt, String hash) {}

    public static Hashed hash(String pin) {
        if (pin == null || !PIN.matcher(pin).matches()) throw new IllegalArgumentException("PIN must be 4-6 digits");
        byte[] salt = new byte[16];
        Crypto.rng().nextBytes(salt);
        return new Hashed(Crypto.b64(salt), derive(pin, salt));
    }

    public static boolean verify(String pin, String saltB64, String expectedHash) {
        if (pin == null || !PIN.matcher(pin).matches()) return false;
        String actual = derive(pin, Crypto.unb64(saltB64));
        return MessageDigest.isEqual(actual.getBytes(), expectedHash.getBytes());
    }

    private static String derive(String pin, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, 256);
            return Crypto.b64(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
