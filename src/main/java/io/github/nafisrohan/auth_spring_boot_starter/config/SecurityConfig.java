package io.github.nafisrohan.auth_spring_boot_starter.config;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.filter.SessionAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
public class SecurityConfig {

    private final SessionAuthStrategy sessionAuthStrategy;

    public SecurityConfig(SessionAuthStrategy sessionAuthStrategy) {
        this.sessionAuthStrategy = sessionAuthStrategy;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) //Store the CSRF token in a cookie
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()) //This tells Spring how to look for/use the CSRF token from incoming requests.
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                    .addFilterBefore(new SessionAuthFilter(sessionAuthStrategy),
                        UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}