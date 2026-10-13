package com.demo.upimesh.protocol;

import java.math.BigDecimal;

import static com.demo.upimesh.protocol.Protocol.nz;

/**
 * Server-signed final outcome for one packet. Bridges gossip it back into the mesh:
 * the receiver flips "Pending" to "Settled"/"Rejected", and every relay that still
 * holds the packet (matched by {@code packetHash}) deletes it.
 *
 * @param status SETTLED or REJECTED
 */
public record SettlementReceipt(
        String packetHash,
        String status,
        String reason,
        String senderVpa,
        String receiverVpa,
        BigDecimal amount,
        String deviceId,
        Long counter,
        String walletCertId,
        long settledAt,
        String signingKeyId,
        String signature) {

    public String canonical() {
        return String.join("\n",
                "MESHPAY-RECEIPT-v1",
                packetHash, status, nz(reason), nz(senderVpa), nz(receiverVpa),
                amount == null ? "" : Protocol.fmtAmount(amount),
                nz(deviceId), nz(counter), nz(walletCertId),
                Long.toString(settledAt), signingKeyId);
    }

    public SettlementReceipt withSignature(String sig) {
        return new SettlementReceipt(packetHash, status, reason, senderVpa, receiverVpa, amount,
                deviceId, counter, walletCertId, settledAt, signingKeyId, sig);
    }
}
