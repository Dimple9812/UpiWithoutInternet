package com.demo.upimesh.protocol;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static com.demo.upimesh.protocol.Protocol.*;

/**
 * What the sender's phone signs. Created and signed offline.
 *
 * @param counter      strictly increasing per device; a counter value can be spent once.
 *                     Two different payments with the same (deviceId, counter) = a fork,
 *                     i.e. a cloned or tampered wallet.
 * @param nonce        random per payment, so identical payments still differ.
 * @param signedAt     epoch millis from the phone clock (untrusted; only used for the
 *                     freshness window, never for ordering).
 * @param walletCertId the offline wallet certificate this payment spends from.
 */
public record PaymentInstruction(
        String senderVpa,
        String receiverVpa,
        BigDecimal amount,
        String deviceId,
        long counter,
        String nonce,
        long signedAt,
        String walletCertId) {

    public String canonical() {
        return String.join("\n",
                "MESHPAY-PAY-v1",
                senderVpa, receiverVpa, fmtAmount(amount), deviceId,
                Long.toString(counter), nonce, Long.toString(signedAt), walletCertId);
    }

    /** @return empty list when well-formed. */
    public List<String> problems() {
        List<String> p = new ArrayList<>();
        if (!matches(VPA, senderVpa)) p.add("bad_sender_vpa");
        if (!matches(VPA, receiverVpa)) p.add("bad_receiver_vpa");
        if (senderVpa != null && senderVpa.equalsIgnoreCase(receiverVpa)) p.add("self_payment");
        if (!validAmount(amount)) p.add("bad_amount");
        if (!matches(DEVICE_ID, deviceId)) p.add("bad_device_id");
        if (counter < 0) p.add("bad_counter");
        if (!matches(NONCE, nonce)) p.add("bad_nonce");
        if (signedAt <= 0) p.add("bad_signed_at");
        if (!matches(UUID, walletCertId)) p.add("bad_wallet_cert_id");
        return p;
    }
}
