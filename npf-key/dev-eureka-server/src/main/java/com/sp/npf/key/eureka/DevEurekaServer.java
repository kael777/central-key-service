package com.sp.npf.key.eureka;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

/** 僅供本機／測試環境驗證註冊用，不要部署到正式環境。 */
@SpringBootApplication
@EnableEurekaServer
public class DevEurekaServer {
    public static void main(String[] args) {
        SpringApplication.run(DevEurekaServer.class, args);
    }
}
