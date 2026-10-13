package com.demo.upimesh.domain;

import com.demo.upimesh.protocol.SettlementReceipt;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.Instant;

/** Immutable ledger row: one per packet that was decrypted, settled or rejected. */
@Entity
@Table(name = "payments")
public class Payment {

    public enum Status { SETTLED, REJECTED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String packetHash;

    private String senderVpa;
    private String receiverVpa;
    @Column(precision = 19, scale = 2) private BigDecimal amount;
    private String deviceId;
    private Long counter;
    private String nonce;
    private String walletCertId;
    private Instant signedAt;

    @Column(nullable = false) private Instant settledAt;
    @Column(nullable = false) private String bridgeNodeId;
    @Column(nullable = false) private int hopCount;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    private String reason;

    @Column(nullable = false) private String receiptKeyId;
    @Column(nullable = false, columnDefinition = "text") private String receiptSignature;

    protected Payment() {}

    public Payment(String packetHash, String senderVpa, String receiverVpa, BigDecimal amount, String deviceId,
                   Long counter, String nonce, String walletCertId, Instant signedAt, Instant settledAt,
                   String bridgeNodeId, int hopCount, Status status, String reason) {
        this.packetHash = packetHash;
        this.senderVpa = senderVpa;
        this.receiverVpa = receiverVpa;
        this.amount = amount;
        this.deviceId = deviceId;
        this.counter = counter;
        this.nonce = nonce;
        this.walletCertId = walletCertId;
        this.signedAt = signedAt;
        this.settledAt = settledAt;
        this.bridgeNodeId = bridgeNodeId;
        this.hopCount = hopCount;
        this.status = status;
        this.reason = reason;
    }

    /** The unsigned receipt body; the caller signs {@link SettlementReceipt#canonical()}. */
    public SettlementReceipt receiptBody(String signingKeyId) {
        return new SettlementReceipt(packetHash, status.name(), reason, senderVpa, receiverVpa, amount,
                deviceId, counter, walletCertId, settledAt.toEpochMilli(), signingKeyId, null);
    }

    public SettlementReceipt receipt() {
        return receiptBody(receiptKeyId).withSignature(receiptSignature);
    }

    public void attachReceipt(String keyId, String signature) {
        this.receiptKeyId = keyId;
        this.receiptSignature = signature;
    }

    public Long getId() { return id; }
    public String getPacketHash() { return packetHash; }
    public String getSenderVpa() { return senderVpa; }
    public String getReceiverVpa() { return receiverVpa; }
    public BigDecimal getAmount() { return amount; }
    public String getDeviceId() { return deviceId; }
    public Long getCounter() { return counter; }
    public String getNonce() { return nonce; }
    public String getWalletCertId() { return walletCertId; }
    public Instant getSignedAt() { return signedAt; }
    public Instant getSettledAt() { return settledAt; }
    public String getBridgeNodeId() { return bridgeNodeId; }
    public int getHopCount() { return hopCount; }
    public Status getStatus() { return status; }
    public String getReason() { return reason; }
    public String getReceiptKeyId() { return receiptKeyId; }
}
