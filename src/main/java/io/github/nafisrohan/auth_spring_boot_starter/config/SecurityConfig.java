package io.github.nafisrohan.auth_spring_boot_starter.config;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.filter.JwtAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.filter.SessionAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
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
    private final JwtService jwtService;

    public SecurityConfig(SessionAuthStrategy sessionAuthStrategy, JwtService jwtService) {
        this.sessionAuthStrategy = sessionAuthStrategy;
        this.jwtService = jwtService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
//
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//Store the CSRF token in a cookie
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())///This tells Spring how to look for/use the CSRF token from incoming requests.
                        .ignoringRequestMatchers("/auth/jwt/**") // JWT uses Authorization header, not cookies — CSRF doesn't apply
                )
                .authorizeHttpRequests(auth -> auth
//                       .requestMatchers("/auth/**").permitAll()
                       .requestMatchers("/auth/**", "/jwt/**").permitAll()
                       .anyRequest().authenticated()
                )
                .addFilterBefore(new SessionAuthFilter(sessionAuthStrategy),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthFilter(jwtService),
                        UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}