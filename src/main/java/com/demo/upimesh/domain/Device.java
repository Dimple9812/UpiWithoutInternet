package com.demo.upimesh.domain;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "devices")
public class Device {

    public enum Status {
        ACTIVE,
        /** A counter fork was seen: the wallet was probably cloned. Payments within the reserve still settle. */
        FLAGGED,
        /** Lost/stolen: new payments are rejected. */
        REVOKED
    }

    @Id
    private String deviceId;

    @Column(nullable = false)
    private String vpa;

    @Column(nullable = false, columnDefinition = "text")
    private String publicKey;

    @Column(nullable = false)
    private String keyAlgorithm;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    private String flaggedReason;

    @Column(nullable = false)
    private Instant registeredAt;

    protected Device() {}

    public Device(String deviceId, String vpa, String publicKey, String keyAlgorithm, Instant registeredAt) {
        this.deviceId = deviceId;
        this.vpa = vpa;
        this.publicKey = publicKey;
        this.keyAlgorithm = keyAlgorithm;
        this.status = Status.ACTIVE;
        this.registeredAt = registeredAt;
    }

    public String getDeviceId() { return deviceId; }
    public String getVpa() { return vpa; }
    public String getPublicKey() { return publicKey; }
    public String getKeyAlgorithm() { return keyAlgorithm; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getFlaggedReason() { return flaggedReason; }
    public void setFlaggedReason(String flaggedReason) { this.flaggedReason = flaggedReason; }
    public Instant getRegisteredAt() { return registeredAt; }
}
