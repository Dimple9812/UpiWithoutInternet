package com.demo.upimesh.protocol;

/**
 * Handed directly from sender to receiver (e.g. over a short BLE/NFC session or QR)
 * at payment time, in the clear. Lets the receiver check, offline, that the payment
 * is authorised by a real device with reserved funds. See {@code IouVerifier}.
 */
public record OfflineIou(SignedEnvelope envelope, WalletCertificate certificate) {}
