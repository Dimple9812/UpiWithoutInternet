package com.demo.upimesh.keys;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Everything the server does with its own keys goes through here, so the storage
 * can be swapped for AWS KMS, GCP KMS or HashiCorp Vault Transit without touching
 * protocol code. {@link DbKeyVault} is the bundled implementation.
 *
 * <ul>
 *   <li>ENCRYPTION keys (RSA): phones encrypt packets to the active one. After rotation
 *       the old key keeps decrypting for a grace period so packets already in the mesh
 *       still settle.</li>
 *   <li>SIGNING keys (EC P-256): sign wallet certificates and settlement receipts. Old
 *       signing public keys stay published forever so old receipts remain verifiable.</li>
 * </ul>
 */
public interface KeyVault {

    enum Purpose { ENCRYPTION, SIGNING }

    record PublicKeyInfo(String keyId, Purpose purpose, String algorithm, String publicKey,
                         String status, Instant createdAt, Instant retiredAt) {}

    record Signed(String keyId, String signature) {}

    PublicKeyInfo activeKey(Purpose purpose);

    /** Private key for an ENCRYPTION keyId that is active or retired within the grace period. */
    Optional<PrivateKey> decryptionKey(String keyId);

    /**
     * Signs with the active SIGNING key. The message usually embeds the signing keyId,
     * so the caller builds it from the keyId it is given.
     */
    Signed sign(Function<String, String> canonicalForKeyId);

    Optional<PublicKey> signingPublicKey(String keyId);

    PublicKeyInfo rotate(Purpose purpose);

    List<PublicKeyInfo> publicKeys();

    /** Drop in-memory caches, as a restart would. */
    void reload();
}
