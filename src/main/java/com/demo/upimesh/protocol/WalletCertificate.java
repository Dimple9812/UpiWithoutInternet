package com.demo.upimesh.protocol;

import java.math.BigDecimal;

import static com.demo.upimesh.protocol.Protocol.fmtAmount;

/**
 * Server-signed statement: "this device may spend up to {@code offlineLimit} offline,
 * and that money is already reserved on the server".
 *
 * It carries the device public key so a receiver can verify a sender's IOU with
 * no internet: check the server signature on the certificate (server signing keys
 * are cached during onboarding), then the device signature on the instruction.
 */
public record WalletCertificate(
        String certId,
        String vpa,
        String deviceId,
        String devicePublicKey,
        BigDecimal offlineLimit,
        BigDecimal perTxnCap,
        long counterStart,
        long issuedAt,
        long expiresAt,
        String signingKeyId,
        String signature) {

    public String canonical() {
        return String.join("\n",
                "MESHPAY-WALLET-v1",
                certId, vpa, deviceId, devicePublicKey,
                fmtAmount(offlineLimit), fmtAmount(perTxnCap),
                Long.toString(counterStart), Long.toString(issuedAt), Long.toString(expiresAt),
                signingKeyId);
    }

    public WalletCertificate withSignature(String keyId, String sig) {
        return new WalletCertificate(certId, vpa, deviceId, devicePublicKey, offlineLimit, perTxnCap,
                counterStart, issuedAt, expiresAt, keyId, sig);
    }
}
