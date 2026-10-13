package com.demo.upimesh.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;

/**
 * Hybrid encryption: a fresh AES-256-GCM key per packet, wrapped with RSA-OAEP-SHA256.
 *
 * <pre>
 * wire = [1 byte version=1][RSA-wrapped AES key (modulus bytes)][12 byte IV][ciphertext || 16 byte tag]
 * AAD  = "MESHPAY-ENC-v1|" + keyId
 * </pre>
 *
 * Binding the keyId into the GCM AAD means a relay that rewrites the outer
 * {@code keyId} field makes decryption fail instead of silently routing the
 * packet to a different key.
 */
public final class HybridCipher {

    public static final byte VERSION = 1;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private HybridCipher() {}

    public static byte[] encrypt(byte[] plaintext, PublicKey rsaKey, String keyId) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, Crypto.rng());
            SecretKey aes = kg.generateKey();

            byte[] iv = new byte[IV_BYTES];
            Crypto.rng().nextBytes(iv);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, aes, new GCMParameterSpec(TAG_BITS, iv));
            gcm.updateAAD(aad(keyId));
            byte[] ct = gcm.doFinal(plaintext);

            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.ENCRYPT_MODE, rsaKey, OAEP);
            byte[] wrapped = rsa.doFinal(aes.getEncoded());

            return ByteBuffer.allocate(1 + wrapped.length + IV_BYTES + ct.length)
                    .put(VERSION).put(wrapped).put(iv).put(ct).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    /** @throws GeneralSecurityException on any tampering, wrong key, wrong keyId, or truncation. */
    public static byte[] decrypt(byte[] wire, PrivateKey rsaKey, String keyId) throws GeneralSecurityException {
        int wrappedLen = (((RSAKey) rsaKey).getModulus().bitLength() + 7) / 8;
        if (wire.length < 1 + wrappedLen + IV_BYTES + TAG_BITS / 8) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(wire);
        if (buf.get() != VERSION) throw new GeneralSecurityException("unsupported wire version");
        byte[] wrapped = new byte[wrappedLen];
        byte[] iv = new byte[IV_BYTES];
        byte[] ct = new byte[buf.remaining() - wrappedLen - IV_BYTES];
        buf.get(wrapped).get(iv).get(ct);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, rsaKey, OAEP);
        SecretKey aes = new SecretKeySpec(rsa.doFinal(wrapped), "AES");

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(TAG_BITS, iv));
        gcm.updateAAD(aad(keyId));
        return gcm.doFinal(ct);
    }

    private static byte[] aad(String keyId) {
        return ("MESHPAY-ENC-v1|" + keyId).getBytes(StandardCharsets.UTF_8);
    }
}
