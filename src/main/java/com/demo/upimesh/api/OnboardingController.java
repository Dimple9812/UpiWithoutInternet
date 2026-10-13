package com.demo.upimesh.api;

import com.demo.upimesh.domain.Device;
import com.demo.upimesh.keys.KeyVault;
import com.demo.upimesh.protocol.WalletCertificate;
import com.demo.upimesh.service.OnboardingService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/** ONLINE endpoints a phone calls while it still has connectivity. */
@RestController
@RequestMapping("/api/v1")
public class OnboardingController {

    private final OnboardingService onboarding;
    private final KeyVault vault;

    public OnboardingController(OnboardingService onboarding, KeyVault vault) {
        this.onboarding = onboarding;
        this.vault = vault;
    }

    public record RegisterDeviceRequest(@NotBlank String vpa, @NotBlank String deviceId,
                                        @NotBlank String publicKey, @NotBlank String pin) {}

    public record RevokeDeviceRequest(@NotBlank String vpa, @NotBlank String pin) {}

    public record LoadWalletRequest(@NotBlank String vpa, @NotBlank String deviceId, @NotNull BigDecimal amount,
                                    BigDecimal perTxnCap, @NotBlank String pin) {}

    public record DeviceView(String deviceId, String vpa, String status) {
        static DeviceView of(Device d) { return new DeviceView(d.getDeviceId(), d.getVpa(), d.getStatus().name()); }
    }

    /**
     * Keys a phone caches before going offline: the active encryption key (to encrypt
     * packets to) and every signing public key (to verify certificates and receipts).
     */
    @GetMapping("/keys")
    public Map<String, Object> keys() {
        KeyVault.PublicKeyInfo enc = vault.activeKey(KeyVault.Purpose.ENCRYPTION);
        List<Map<String, Object>> signing = vault.publicKeys().stream()
                .filter(k -> k.purpose() == KeyVault.Purpose.SIGNING)
                .map(k -> Map.<String, Object>of("keyId", k.keyId(), "algorithm", k.algorithm(),
                        "publicKey", k.publicKey(), "status", k.status()))
                .toList();
        return Map.of(
                "encryption", Map.of("keyId", enc.keyId(), "algorithm", enc.algorithm(), "publicKey", enc.publicKey()),
                "signing", signing);
    }

    @PostMapping("/devices")
    @ResponseStatus(HttpStatus.CREATED)
    public DeviceView register(@Valid @RequestBody RegisterDeviceRequest r) {
        return DeviceView.of(onboarding.registerDevice(r.vpa(), r.deviceId(), r.publicKey(), r.pin()));
    }

    @PostMapping("/devices/{deviceId}/revoke")
    public DeviceView revoke(@PathVariable String deviceId, @Valid @RequestBody RevokeDeviceRequest r) {
        return DeviceView.of(onboarding.revokeDevice(deviceId, r.vpa(), r.pin()));
    }

    @PostMapping("/wallets")
    @ResponseStatus(HttpStatus.CREATED)
    public WalletCertificate loadWallet(@Valid @RequestBody LoadWalletRequest r) {
        return onboarding.issueWallet(r.vpa(), r.deviceId(), r.amount(), r.perTxnCap(), r.pin());
    }

    @GetMapping("/wallets/{certId}")
    public WalletCertificate wallet(@PathVariable String certId) {
        return onboarding.certificate(certId);
    }
}
