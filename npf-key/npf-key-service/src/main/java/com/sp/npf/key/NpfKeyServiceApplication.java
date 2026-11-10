package com.sp.npf.key;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.sp.npf.key.config.NpfProperties;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(NpfProperties.class)
public class NpfKeyServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(NpfKeyServiceApplication.class, args);
    }
}
