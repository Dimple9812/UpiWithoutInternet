package com.demo.upimesh.domain;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, String> {

    /** SELECT ... FOR UPDATE. Postgres lock_timeout (set per connection) turns a stuck lock into a retryable error. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from Account a where a.vpa = :vpa")
    Optional<Account> lockByVpa(@Param("vpa") String vpa);
}
