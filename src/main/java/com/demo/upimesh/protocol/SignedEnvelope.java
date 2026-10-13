package com.demo.upimesh.protocol;

/**
 * The plaintext that gets hybrid-encrypted to the server: the instruction plus the
 * device's ECDSA signature over {@link PaymentInstruction#canonical()}.
 *
 * Sign-then-encrypt: relays see neither the instruction nor the signature, and the
 * server can prove who authorised the payment (encryption alone cannot, because the
 * server's encryption key is public).
 */
public record SignedEnvelope(PaymentInstruction instruction, String signature) {}
