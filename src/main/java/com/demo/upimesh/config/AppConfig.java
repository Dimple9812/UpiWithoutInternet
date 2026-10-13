package com.demo.upimesh.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.time.Clock;

@Configuration
@EnableScheduling
@EnableConfigurationProperties(MeshPayProperties.class)
public class AppConfig {

    /** Injected everywhere time matters, so tests can control it. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
