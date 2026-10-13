package com.demo.upimesh.sim;

import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.protocol.*;

import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;

/**
 * What a RECEIVER's phone can check with no internet, using only the server
 * signing public keys it cached during onboarding.
 *
 * A valid IOU proves: the server issued this wallet with reserved money, the payment
 * was signed by that wallet's device key, and it fits the per-txn cap. It does NOT
 * prove the sender hasn't promised the same money to someone else — only the server
 * sees all payments. That residual risk is bounded by the reserved limit and by the
 * hardware-backed key (a cloned wallet needs the key to leave the Keystore).
 */
public final class OfflineVerifier {

    private OfflineVerifier() {}

    /** @return empty if valid, otherwise the reason. */
    public static Optional<String> checkIou(OfflineIou iou, String expectedReceiverVpa,
                                            Map<String, PublicKey> serverSigningKeys, long nowMillis) {
        WalletCertificate c = iou.certificate();
        PaymentInstruction in = iou.envelope().instruction();

        PublicKey serverKey = serverSigningKeys.get(c.signingKeyId());
        if (serverKey == null) return Optional.of("unknown_server_key");
        if (!Crypto.verify(serverKey, c.canonical(), c.signature())) return Optional.of("bad_certificate");
        if (nowMillis > c.expiresAt()) return Optional.of("wallet_expired");

        if (!in.walletCertId().equals(c.certId())) return Optional.of("wallet_mismatch");
        if (!in.deviceId().equals(c.deviceId()) || !in.senderVpa().equals(c.vpa())) return Optional.of("wallet_mismatch");
        if (!in.receiverVpa().equals(expectedReceiverVpa)) return Optional.of("not_for_me");
        if (!in.problems().isEmpty()) return Optional.of(in.problems().get(0));
        if (in.amount().compareTo(c.perTxnCap()) > 0) return Optional.of("over_per_txn_cap");
        if (in.counter() < c.counterStart()) return Optional.of("counter_below_wallet_start");

        PublicKey deviceKey = Crypto.ecPublicKey(c.devicePublicKey());
        if (!Crypto.verify(deviceKey, in.canonical(), iou.envelope().signature())) return Optional.of("bad_signature");
        return Optional.empty();
    }

    public static boolean checkReceipt(SettlementReceipt r, Map<String, PublicKey> serverSigningKeys) {
        PublicKey k = serverSigningKeys.get(r.signingKeyId());
        return k != null && Crypto.verify(k, r.canonical(), r.signature());
    }
}
