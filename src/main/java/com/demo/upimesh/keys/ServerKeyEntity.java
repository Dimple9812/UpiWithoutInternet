package com.demo.upimesh.keys;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "server_keys")
public class ServerKeyEntity {

    @Id
    private String keyId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private KeyVault.Purpose purpose;

    @Column(nullable = false) private String algorithm;
    @Column(nullable = false, columnDefinition = "text") private String publicKey;
    @Column(nullable = false, columnDefinition = "text") private String wrappedPrivateKey;
    @Column(nullable = false) private String status;
    @Column(nullable = false) private Instant createdAt;
    private Instant retiredAt;

    protected ServerKeyEntity() {}

    public ServerKeyEntity(String keyId, KeyVault.Purpose purpose, String algorithm, String publicKey,
                           String wrappedPrivateKey, Instant createdAt) {
        this.keyId = keyId;
        this.purpose = purpose;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.wrappedPrivateKey = wrappedPrivateKey;
        this.status = "ACTIVE";
        this.createdAt = createdAt;
    }

    public void retire(Instant at) {
        this.status = "RETIRED";
        this.retiredAt = at;
    }

    public String getKeyId() { return keyId; }
    public KeyVault.Purpose getPurpose() { return purpose; }
    public String getAlgorithm() { return algorithm; }
    public String getPublicKey() { return publicKey; }
    public String getWrappedPrivateKey() { return wrappedPrivateKey; }
    public String getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRetiredAt() { return retiredAt; }
}
