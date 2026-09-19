package io.github.nafisrohan.auth_spring_boot_starter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "unifyauth")
public class AuthProperties {

    private String strategy = "session"; // default, if consumer doesn't specify

    public String getStrategy() {
        return strategy;
    }

    public void setStrategy(String strategy) {
        this.strategy = strategy;
    }
}