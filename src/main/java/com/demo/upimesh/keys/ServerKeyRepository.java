package com.demo.upimesh.keys;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ServerKeyRepository extends JpaRepository<ServerKeyEntity, String> {

    Optional<ServerKeyEntity> findFirstByPurposeAndStatus(KeyVault.Purpose purpose, String status);

    List<ServerKeyEntity> findAllByOrderByCreatedAtDesc();
}
