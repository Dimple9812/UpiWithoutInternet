package com.demo.upimesh.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.Instant;

/** Simulated bank account (in reality this lives in the issuer bank's core system). */
@Entity
@Table(name = "accounts")
public class Account {

    @Id
    private String vpa;

    @Column(nullable = false)
    private String holderName;

    @Column(nullable = false, precision = 19, scale = 2)
    private BigDecimal balance;

    @JsonIgnore @Column(nullable = false)
    private String pinSalt;

    @JsonIgnore @Column(nullable = false)
    private String pinHash;

    @Version
    private long version;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected Account() {}

    public Account(String vpa, String holderName, BigDecimal balance, String pinSalt, String pinHash) {
        this.vpa = vpa;
        this.holderName = holderName;
        this.balance = balance;
        this.pinSalt = pinSalt;
        this.pinHash = pinHash;
    }

    public String getVpa() { return vpa; }
    public String getHolderName() { return holderName; }
    public BigDecimal getBalance() { return balance; }
    public void setBalance(BigDecimal balance) { this.balance = balance; }
    public String getPinSalt() { return pinSalt; }
    public String getPinHash() { return pinHash; }
    public long getVersion() { return version; }
    public Instant getCreatedAt() { return createdAt; }
}
