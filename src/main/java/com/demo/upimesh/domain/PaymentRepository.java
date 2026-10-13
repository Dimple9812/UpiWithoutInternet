package com.demo.upimesh.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface PaymentRepository extends JpaRepository<Payment, Long> {

    Optional<Payment> findByPacketHash(String packetHash);

    Optional<Payment> findByDeviceIdAndCounterAndStatus(String deviceId, Long counter, Payment.Status status);

    List<Payment> findTop20ByOrderByIdDesc();

    @Query("select coalesce(max(p.counter), -1) from Payment p where p.deviceId = :deviceId and p.status = 'SETTLED'")
    long maxSettledCounter(@Param("deviceId") String deviceId);
}
