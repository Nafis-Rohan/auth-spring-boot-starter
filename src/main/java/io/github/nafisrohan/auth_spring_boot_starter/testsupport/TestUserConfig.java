package io.github.nafisrohan.auth_spring_boot_starter.testsupport;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Test-only in-memory user for manually exercising form login and WebAuthn
 * registration during local development. NEVER enabled by default — only
 * activates when explicitly opted into via application.yml, and must never
 * be enabled in a real deployment.
 */
@Configuration
@ConditionalOnProperty(name = "myauth.test-user.enabled", havingValue = "true")
public class TestUserConfig {


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("nafis")
                .password("password")
                .roles("USER")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("adminpass")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}