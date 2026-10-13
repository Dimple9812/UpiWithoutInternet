package com.demo.upimesh.service;

import com.demo.upimesh.config.MeshPayProperties;
import com.demo.upimesh.crypto.Crypto;
import com.demo.upimesh.domain.*;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.Protocol;
import com.demo.upimesh.protocol.WalletCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * The ONLINE half of the protocol: register a device key, reserve money into an
 * offline wallet and hand back a signed certificate, and later close expired
 * wallets and refund whatever was not spent.
 */
@Service
public class OnboardingService {

    private static final Logger log = LoggerFactory.getLogger(OnboardingService.class);

    private final AccountRepository accounts;
    private final DeviceRepository devices;
    private final OfflineWalletRepository wallets;
    private final PaymentRepository payments;
    private final KeyVault vault;
    private final MeshPayProperties props;
    private final Clock clock;
    private final TransactionTemplate tx;

    public OnboardingService(AccountRepository accounts, DeviceRepository devices, OfflineWalletRepository wallets,
                             PaymentRepository payments, KeyVault vault, MeshPayProperties props, Clock clock,
                             TransactionTemplate tx) {
        this.accounts = accounts;
        this.devices = devices;
        this.wallets = wallets;
        this.payments = payments;
        this.vault = vault;
        this.props = props;
        this.clock = clock;
        this.tx = tx;
    }

    // ----------------------------------------------------------------- devices

    @Transactional
    public Device registerDevice(String vpa, String deviceId, String publicKeyB64, String pin) {
        if (!Protocol.matches(Protocol.DEVICE_ID, deviceId)) throw ApiException.badRequest("bad_device_id", "invalid deviceId");
        Account acc = authenticate(vpa, pin);
        PublicKey key;
        try {
            key = Crypto.ecPublicKey(publicKeyB64);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("bad_public_key", "publicKey must be a base64 X.509 EC key");
        }
        if (!Crypto.isP256(key)) throw ApiException.badRequest("bad_public_key", "only EC P-256 device keys are accepted");
        if (devices.existsById(deviceId)) throw ApiException.conflict("device_exists", "deviceId already registered");

        Device d = devices.save(new Device(deviceId, acc.getVpa(), publicKeyB64, Crypto.DEVICE_KEY_ALG, clock.instant()));
        log.atInfo().addKeyValue("vpa", vpa).addKeyValue("deviceId", deviceId).log("Device registered");
        return d;
    }

    /** Lost or stolen phone: new payments from it are rejected. */
    @Transactional
    public Device revokeDevice(String deviceId, String vpa, String pin) {
        authenticate(vpa, pin);
        Device d = devices.findById(deviceId)
                .filter(x -> x.getVpa().equals(vpa))
                .orElseThrow(() -> ApiException.notFound("unknown_device", "device not found for this VPA"));
        d.setStatus(Device.Status.REVOKED);
        return d;
    }

    // ----------------------------------------------------------------- wallets

    /**
     * Moves {@code amount} out of the main balance into a wallet reserved for one device,
     * and returns the server-signed certificate the phone will spend from offline.
     */
    @Transactional
    public WalletCertificate issueWallet(String vpa, String deviceId, BigDecimal amount, BigDecimal perTxnCap, String pin) {
        authenticate(vpa, pin);
        MeshPayProperties.Wallet cfg = props.wallet();

        if (!Protocol.validAmount(amount) || amount.compareTo(cfg.maxLimit()) > 0) {
            throw ApiException.badRequest("bad_amount", "offline amount must be > 0 and <= " + cfg.maxLimit());
        }
        BigDecimal cap = perTxnCap == null ? cfg.maxPerTxn().min(amount) : perTxnCap;
        if (!Protocol.validAmount(cap) || cap.compareTo(amount) > 0 || cap.compareTo(cfg.maxPerTxn()) > 0) {
            throw ApiException.badRequest("bad_per_txn_cap", "perTxnCap must be > 0, <= amount and <= " + cfg.maxPerTxn());
        }
        amount = amount.setScale(2, RoundingMode.UNNECESSARY);
        cap = cap.setScale(2, RoundingMode.UNNECESSARY);

        Device device = devices.findById(deviceId)
                .filter(d -> d.getVpa().equals(vpa))
                .orElseThrow(() -> ApiException.notFound("unknown_device", "device not registered to this VPA"));
        if (device.getStatus() == Device.Status.REVOKED) throw ApiException.conflict("device_revoked", "device is revoked");
        if (wallets.findFirstByDeviceIdAndStatus(deviceId, OfflineWallet.Status.ACTIVE).isPresent()) {
            throw ApiException.conflict("wallet_active", "device already has an active offline wallet");
        }

        Account acc = accounts.lockByVpa(vpa).orElseThrow();
        if (acc.getBalance().compareTo(amount) < 0) {
            throw ApiException.unprocessable("insufficient_balance", "not enough balance to reserve");
        }
        acc.setBalance(acc.getBalance().subtract(amount));

        // Counters never go backwards for a device, across all of its wallets.
        long counterStart = Math.max(payments.maxSettledCounter(deviceId), wallets.maxCounterStart(deviceId)) + 1;
        Instant now = clock.instant();
        WalletCertificate unsigned = new WalletCertificate(
                UUID.randomUUID().toString(), vpa, deviceId, device.getPublicKey(), amount, cap, counterStart,
                now.toEpochMilli(), now.plus(cfg.validity()).toEpochMilli(), null, null);
        KeyVault.Signed sig = vault.sign(keyId -> unsigned.withSignature(keyId, null).canonical());
        WalletCertificate cert = unsigned.withSignature(sig.keyId(), sig.signature());

        try {
            wallets.saveAndFlush(new OfflineWallet(cert.certId(), vpa, deviceId, amount, cap, counterStart, now,
                    Instant.ofEpochMilli(cert.expiresAt()), sig.keyId(), sig.signature()));
        } catch (DataIntegrityViolationException raced) {
            throw ApiException.conflict("wallet_active", "device already has an active offline wallet");
        }
        log.atInfo().addKeyValue("vpa", vpa).addKeyValue("deviceId", deviceId)
                .addKeyValue("certId", cert.certId()).addKeyValue("amount", amount).log("Offline wallet issued");
        return cert;
    }

    public WalletCertificate certificate(String certId) {
        OfflineWallet w = wallets.findById(certId)
                .orElseThrow(() -> ApiException.notFound("unknown_wallet", "wallet not found"));
        Device d = devices.findById(w.getDeviceId()).orElseThrow();
        return new WalletCertificate(w.getCertId(), w.getVpa(), w.getDeviceId(), d.getPublicKey(), w.getOfflineLimit(),
                w.getPerTxnCap(), w.getCounterStart(), w.getIssuedAt().toEpochMilli(), w.getExpiresAt().toEpochMilli(),
                w.getSigningKeyId(), w.getSignature());
    }

    /**
     * A wallet is closed only after {@code expiresAt + packetMaxAge}: by then no packet it
     * signed can still be valid, so refunding the remainder cannot race a settlement.
     */
    @Scheduled(fixedDelayString = "${meshpay.wallet.sweep-interval:PT5M}")
    public void closeExpiredWallets() {
        Instant cutoff = clock.instant().minus(props.packetMaxAge());
        for (String id : wallets.findExpiredActiveIds(cutoff)) {
            closeIfExpired(id);
        }
    }

    public boolean closeIfExpired(String certId) {
        Boolean closed = tx.execute(s -> {
            OfflineWallet w = wallets.lockById(certId).orElse(null);
            if (w == null || w.getStatus() != OfflineWallet.Status.ACTIVE) return false;
            if (!w.getExpiresAt().plus(props.packetMaxAge()).isBefore(clock.instant())) return false;
            Account acc = accounts.lockByVpa(w.getVpa()).orElseThrow();
            acc.setBalance(acc.getBalance().add(w.getRemaining()));
            log.atInfo().addKeyValue("certId", certId).addKeyValue("refunded", w.getRemaining())
                    .log("Offline wallet closed");
            w.close(clock.instant());
            return true;
        });
        return Boolean.TRUE.equals(closed);
    }

    // ----------------------------------------------------------------- helpers

    private Account authenticate(String vpa, String pin) {
        Account acc = vpa == null ? null : accounts.findById(vpa).orElse(null);
        if (acc == null || !PinHasher.verify(pin, acc.getPinSalt(), acc.getPinHash())) {
            throw ApiException.unauthorized("bad_credentials", "unknown VPA or wrong PIN");
        }
        return acc;
    }
}
