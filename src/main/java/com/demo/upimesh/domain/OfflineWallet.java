package com.demo.upimesh.domain;

import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Server-side record of an offline wallet. {@code remaining} is the reserved money
 * not yet claimed by settled payments; it can only go down while ACTIVE, and the
 * leftover is refunded to the main balance when the wallet is closed.
 */
@Entity
@Table(name = "offline_wallets")
public class OfflineWallet {

    public enum Status { ACTIVE, CLOSED }

    @Id
    private String certId;

    @Column(nullable = false) private String vpa;
    @Column(nullable = false) private String deviceId;
    @Column(nullable = false, precision = 19, scale = 2) private BigDecimal offlineLimit;
    @Column(nullable = false, precision = 19, scale = 2) private BigDecimal perTxnCap;
    @Column(nullable = false, precision = 19, scale = 2) private BigDecimal remaining;
    @Column(nullable = false) private long counterStart;
    @Column(nullable = false) private Instant issuedAt;
    @Column(nullable = false) private Instant expiresAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @Column(nullable = false) private String signingKeyId;
    @Column(nullable = false, columnDefinition = "text") private String signature;
    private Instant closedAt;
    @Column(precision = 19, scale = 2) private BigDecimal refunded;

    @Version
    private long version;

    protected OfflineWallet() {}

    public OfflineWallet(String certId, String vpa, String deviceId, BigDecimal offlineLimit, BigDecimal perTxnCap,
                         long counterStart, Instant issuedAt, Instant expiresAt,
                         String signingKeyId, String signature) {
        this.certId = certId;
        this.vpa = vpa;
        this.deviceId = deviceId;
        this.offlineLimit = offlineLimit;
        this.perTxnCap = perTxnCap;
        this.remaining = offlineLimit;
        this.counterStart = counterStart;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = Status.ACTIVE;
        this.signingKeyId = signingKeyId;
        this.signature = signature;
    }

    public void close(Instant at) {
        this.refunded = remaining;
        this.remaining = BigDecimal.ZERO.setScale(2);
        this.status = Status.CLOSED;
        this.closedAt = at;
    }

    public String getCertId() { return certId; }
    public String getVpa() { return vpa; }
    public String getDeviceId() { return deviceId; }
    public BigDecimal getOfflineLimit() { return offlineLimit; }
    public BigDecimal getPerTxnCap() { return perTxnCap; }
    public BigDecimal getRemaining() { return remaining; }
    public void setRemaining(BigDecimal remaining) { this.remaining = remaining; }
    public long getCounterStart() { return counterStart; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Status getStatus() { return status; }
    public String getSigningKeyId() { return signingKeyId; }
    public String getSignature() { return signature; }
    public Instant getClosedAt() { return closedAt; }
    public BigDecimal getRefunded() { return refunded; }
}
