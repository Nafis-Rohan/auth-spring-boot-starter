package io.github.nafisrohan.auth_spring_boot_starter.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration //meaning it activates automatically when the library is imported, without the consumer needing to manually scan or import it.
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {

    @Bean
    public AuthProperties authProperties() {
        return new AuthProperties();
    }
}