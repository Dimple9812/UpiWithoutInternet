package com.demo.upimesh.service;

import com.demo.upimesh.config.MeshPayProperties;
import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.domain.*;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.PaymentInstruction;
import com.demo.upimesh.protocol.SignedEnvelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Verifies a decrypted, signed payment and settles it — or records why not — in ONE
 * database transaction. Every outcome is a row in {@code payments} with a signed
 * receipt; nothing here throws for a bad payment.
 *
 * Order of checks (cheapest and most "who are you" first):
 * <ol>
 *   <li>well-formed fields</li>
 *   <li>device exists, belongs to the sender, not revoked</li>
 *   <li>device signature (the step that stops anyone spending someone else's money)</li>
 *   <li>freshness window</li>
 *   <li>wallet: locked FOR UPDATE, owned by this device, active, not expired, counter in range</li>
 *   <li>counter reuse: same counter already settled = fork / double-spend attempt</li>
 *   <li>per-txn cap and remaining reserved balance</li>
 *   <li>receiver exists (locked FOR UPDATE), then move the money</li>
 * </ol>
 * Lock order is always wallet → receiver account, so concurrent settlements cannot deadlock.
 */
@Service
public class SettlementService {

    private static final Logger log = LoggerFactory.getLogger(SettlementService.class);

    public record Result(Payment payment, boolean duplicate) {}

    private final AccountRepository accounts;
    private final DeviceRepository devices;
    private final OfflineWalletRepository wallets;
    private final PaymentRepository payments;
    private final KeyVault vault;
    private final MeshPayProperties props;
    private final Clock clock;

    public SettlementService(AccountRepository accounts, DeviceRepository devices, OfflineWalletRepository wallets,
                             PaymentRepository payments, KeyVault vault, MeshPayProperties props, Clock clock) {
        this.accounts = accounts;
        this.devices = devices;
        this.wallets = wallets;
        this.payments = payments;
        this.vault = vault;
        this.props = props;
        this.clock = clock;
    }

    @Transactional
    public Result process(String packetHash, SignedEnvelope env, String bridgeId, int hopCount) {
        PaymentInstruction in = env.instruction();
        Instant now = clock.instant();

        // 1. shape
        List<String> problems = in.problems();
        if (!problems.isEmpty()) return reject(packetHash, in, bridgeId, hopCount, problems.get(0));
        BigDecimal amount = in.amount().setScale(2, RoundingMode.UNNECESSARY);

        // 2. device
        Optional<Device> deviceOpt = devices.findById(in.deviceId());
        if (deviceOpt.isEmpty()) return reject(packetHash, in, bridgeId, hopCount, "unknown_device");
        Device device = deviceOpt.get();
        if (!device.getVpa().equals(in.senderVpa())) return reject(packetHash, in, bridgeId, hopCount, "device_vpa_mismatch");
        if (device.getStatus() == Device.Status.REVOKED) return reject(packetHash, in, bridgeId, hopCount, "device_revoked");

        // 3. signature
        if (!Crypto.verify(Crypto.ecPublicKey(device.getPublicKey()), in.canonical(), env.signature())) {
            log.atWarn().addKeyValue("deviceId", in.deviceId()).addKeyValue("packetHash", packetHash)
                    .log("Bad device signature (forged sender?)");
            return reject(packetHash, in, bridgeId, hopCount, "bad_signature");
        }

        // 4. freshness
        Instant signedAt = Instant.ofEpochMilli(in.signedAt());
        if (signedAt.isBefore(now.minus(props.packetMaxAge()))) return reject(packetHash, in, bridgeId, hopCount, "stale_packet");
        if (signedAt.isAfter(now.plus(props.clockSkew()))) return reject(packetHash, in, bridgeId, hopCount, "future_dated");

        // 5. wallet (row lock serialises every settlement from this device)
        Optional<OfflineWallet> walletOpt = wallets.lockById(in.walletCertId());
        if (walletOpt.isEmpty()) return reject(packetHash, in, bridgeId, hopCount, "unknown_wallet");
        OfflineWallet wallet = walletOpt.get();
        if (!wallet.getDeviceId().equals(in.deviceId()) || !wallet.getVpa().equals(in.senderVpa())) {
            return reject(packetHash, in, bridgeId, hopCount, "wallet_mismatch");
        }
        if (wallet.getStatus() != OfflineWallet.Status.ACTIVE) return reject(packetHash, in, bridgeId, hopCount, "wallet_closed");
        if (signedAt.isAfter(wallet.getExpiresAt())) return reject(packetHash, in, bridgeId, hopCount, "wallet_expired");
        if (in.counter() < wallet.getCounterStart()) return reject(packetHash, in, bridgeId, hopCount, "counter_below_wallet_start");

        // 6. counter reuse
        Optional<Payment> sameCounter = payments.findByDeviceIdAndCounterAndStatus(
                in.deviceId(), in.counter(), Payment.Status.SETTLED);
        if (sameCounter.isPresent()) {
            Payment prior = sameCounter.get();
            if (Objects.equals(prior.getNonce(), in.nonce())) {
                // Same signed payment, re-encrypted into a different ciphertext: not new money.
                return new Result(prior, true);
            }
            device.setStatus(device.getStatus() == Device.Status.REVOKED ? Device.Status.REVOKED : Device.Status.FLAGGED);
            device.setFlaggedReason("counter_fork@" + in.counter());
            log.atWarn().addKeyValue("deviceId", in.deviceId()).addKeyValue("counter", in.counter())
                    .log("Counter fork detected: two different payments share one counter");
            return reject(packetHash, in, bridgeId, hopCount, "counter_reused");
        }

        // 7. limits
        if (amount.compareTo(wallet.getPerTxnCap()) > 0) return reject(packetHash, in, bridgeId, hopCount, "over_per_txn_cap");
        if (amount.compareTo(wallet.getRemaining()) > 0) return reject(packetHash, in, bridgeId, hopCount, "offline_limit_exceeded");

        // 8. receiver + money movement
        Optional<Account> receiverOpt = accounts.lockByVpa(in.receiverVpa());
        if (receiverOpt.isEmpty()) return reject(packetHash, in, bridgeId, hopCount, "unknown_receiver");
        Account receiver = receiverOpt.get();

        wallet.setRemaining(wallet.getRemaining().subtract(amount));
        receiver.setBalance(receiver.getBalance().add(amount));

        Payment p = record(packetHash, in, amount, bridgeId, hopCount, Payment.Status.SETTLED, null);
        log.atInfo().addKeyValue("packetHash", packetHash).addKeyValue("amount", amount)
                .addKeyValue("from", in.senderVpa()).addKeyValue("to", in.receiverVpa())
                .addKeyValue("deviceId", in.deviceId()).addKeyValue("counter", in.counter())
                .addKeyValue("bridge", bridgeId).addKeyValue("hops", hopCount).log("Payment settled");
        return new Result(p, false);
    }

    /** For packets whose plaintext could not even be parsed into an instruction. */
    @Transactional
    public Result rejectUnparsed(String packetHash, String bridgeId, int hopCount, String reason) {
        return reject(packetHash, null, bridgeId, hopCount, reason);
    }

    // ----------------------------------------------------------------- internals

    private Result reject(String packetHash, PaymentInstruction in, String bridgeId, int hopCount, String reason) {
        BigDecimal amount = in == null || !com.demo.upimesh.protocol.Protocol.validAmount(in.amount())
                ? null : in.amount().setScale(2, RoundingMode.UNNECESSARY);
        log.atInfo().addKeyValue("packetHash", packetHash).addKeyValue("reason", reason)
                .addKeyValue("bridge", bridgeId).log("Payment rejected");
        return new Result(record(packetHash, in, amount, bridgeId, hopCount, Payment.Status.REJECTED, reason), false);
    }

    private Payment record(String packetHash, PaymentInstruction in, BigDecimal amount, String bridgeId, int hopCount,
                           Payment.Status status, String reason) {
        Payment p = new Payment(packetHash,
                in == null ? null : clip(in.senderVpa(), 128),
                in == null ? null : clip(in.receiverVpa(), 128),
                amount,
                in == null ? null : clip(in.deviceId(), 64),
                in == null ? null : in.counter(),
                in == null ? null : clip(in.nonce(), 64),
                in == null ? null : clip(in.walletCertId(), 36),
                in == null || in.signedAt() <= 0 ? null : Instant.ofEpochMilli(in.signedAt()),
                clock.instant(), bridgeId, hopCount, status, reason);
        KeyVault.Signed sig = vault.sign(keyId -> p.receiptBody(keyId).canonical());
        p.attachReceipt(sig.keyId(), sig.signature());
        return payments.saveAndFlush(p);
    }

    /** Rejected rows store attacker-supplied text; keep it within column sizes and newline-free. */
    private static String clip(String s, int max) {
        if (s == null) return null;
        String clean = s.replaceAll("[\\r\\n]", "?");
        return clean.length() <= max ? clean : clean.substring(0, max);
    }
}
