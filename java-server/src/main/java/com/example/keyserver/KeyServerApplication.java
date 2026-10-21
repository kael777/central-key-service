package com.example.keyserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class KeyServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(KeyServerApplication.class, args);
    }
}
