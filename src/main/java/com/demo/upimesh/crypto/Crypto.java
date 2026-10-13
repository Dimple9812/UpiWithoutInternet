package com.demo.upimesh.crypto;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Small, dependency-free crypto helpers shared by the server and the reference
 * client ({@code com.demo.upimesh.sim}). Everything here uses JDK providers only,
 * so the same code ports directly to Android.
 *
 * <ul>
 *   <li>Device + server signatures: ECDSA P-256 with SHA-256 ("SHA256withECDSA").
 *       P-256 is supported by every Android Keystore (StrongBox included), unlike
 *       Ed25519 which only arrived in API 33.</li>
 *   <li>Hashing: SHA-256.</li>
 * </ul>
 */
public final class Crypto {

    public static final String SIGNATURE_ALG = "SHA256withECDSA";
    public static final String EC_CURVE = "secp256r1";
    public static final String DEVICE_KEY_ALG = "EC_P256";

    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {}

    public static SecureRandom rng() { return RNG; }

    // ---------------------------------------------------------------- hashing

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(String s) {
        return sha256Hex(s.getBytes(StandardCharsets.UTF_8));
    }

    // ---------------------------------------------------------------- base64

    public static String b64(byte[] data) { return Base64.getEncoder().encodeToString(data); }

    /** Strict decode: rejects whitespace and malformed padding. */
    public static byte[] unb64(String s) {
        if (s == null) throw new IllegalArgumentException("missing base64 value");
        return Base64.getDecoder().decode(s);
    }

    // ---------------------------------------------------------------- EC keys

    public static KeyPair newEcKeyPair() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(EC_CURVE), RNG);
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PublicKey ecPublicKey(String b64X509) {
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(unb64(b64X509)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid EC public key", e);
        }
    }

    public static PrivateKey ecPrivateKey(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid EC private key", e);
        }
    }

    public static PublicKey rsaPublicKey(String b64X509) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(b64X509)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid RSA public key", e);
        }
    }

    public static PrivateKey rsaPrivateKey(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid RSA private key", e);
        }
    }

    /** Only accept keys that really are P-256; anything else is rejected at registration. */
    public static boolean isP256(PublicKey key) {
        if (!(key instanceof java.security.interfaces.ECPublicKey ec)) return false;
        return ec.getParams().getCurve().getField().getFieldSize() == 256
                && ec.getParams().getOrder().bitLength() == 256;
    }

    // ---------------------------------------------------------------- signatures

    public static String sign(PrivateKey key, String canonical) {
        try {
            Signature s = Signature.getInstance(SIGNATURE_ALG);
            s.initSign(key, RNG);
            s.update(canonical.getBytes(StandardCharsets.UTF_8));
            return b64(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Never throws for bad input: a malformed signature simply does not verify. */
    public static boolean verify(PublicKey key, String canonical, String b64Signature) {
        try {
            Signature s = Signature.getInstance(SIGNATURE_ALG);
            s.initVerify(key);
            s.update(canonical.getBytes(StandardCharsets.UTF_8));
            return s.verify(unb64(b64Signature));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
}
