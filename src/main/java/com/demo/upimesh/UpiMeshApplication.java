package com.demo.upimesh;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class UpiMeshApplication {
    public static void main(String[] args) {
        // Ledger timestamps are UTC end to end. This also avoids PostgreSQL rejecting
        // legacy JVM zone names such as "Asia/Calcutta" at connection time.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(UpiMeshApplication.class, args);
    }
}
