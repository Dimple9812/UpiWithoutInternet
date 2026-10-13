package com.demo.upimesh.domain;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface OfflineWalletRepository extends JpaRepository<OfflineWallet, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select w from OfflineWallet w where w.certId = :certId")
    Optional<OfflineWallet> lockById(@Param("certId") String certId);

    Optional<OfflineWallet> findFirstByDeviceIdAndStatus(String deviceId, OfflineWallet.Status status);

    @Query("select w.certId from OfflineWallet w where w.status = 'ACTIVE' and w.expiresAt < :cutoff")
    List<String> findExpiredActiveIds(@Param("cutoff") Instant cutoff);

    @Query("select coalesce(max(w.counterStart), -1) from OfflineWallet w where w.deviceId = :deviceId")
    long maxCounterStart(@Param("deviceId") String deviceId);
}
