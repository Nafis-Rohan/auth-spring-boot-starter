package io.github.nafisrohan.auth_spring_boot_starter.config;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.filter.JwtAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.filter.RateLimitFilter;
import io.github.nafisrohan.auth_spring_boot_starter.filter.SessionAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;

import java.time.Duration;


@Configuration
@EnableMethodSecurity //Turn on security checks on individual methods.
public class SecurityConfig {


    @Value("${webauthn.rp-id}")
    private String webAuthnRpId;

    @Value("${webauthn.allowed-origins}")
    private String webAuthnAllowedOrigin;

    @Value("${rate-limit.requests-per-minute:5}")
    private int rateLimitRequestsPerMinute;


    private final SessionAuthStrategy sessionAuthStrategy;
    private final JwtService jwtService;

    public SecurityConfig(SessionAuthStrategy sessionAuthStrategy, JwtService jwtService) {
        this.sessionAuthStrategy = sessionAuthStrategy;
        this.jwtService = jwtService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   @Value("${myauth.test-user.enabled:false}") boolean testUserEnabled) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//Store the CSRF token in a cookie
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())///This tells Spring how to look for/use the CSRF token from incoming requests.
                        .ignoringRequestMatchers("/auth/jwt/**") // JWT uses Authorization header, not cookies — CSRF doesn't apply
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/mfa/**").authenticated()
                        .requestMatchers("/auth/**", "/jwt/**", "/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/auth/oauth2/success", true)
                        .authorizationEndpoint(endpoint -> endpoint
                                .authorizationRequestResolver(authorizationRequestResolver(clientRegistrationRepository))
                        )
                )
                //webAuthn Enables/configures WebAuthn in Spring Security.
                .webAuthn(webAuthn -> webAuthn
                        .rpId(webAuthnRpId) //Which website is allowed to use this passkey? So the passkey is associated with localhost.
                        .allowedOrigins(webAuthnAllowedOrigin) //WebAuthn will accept authentication requests originating from http://localhost:8080.
                )
                .addFilterBefore(new SessionAuthFilter(sessionAuthStrategy),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthFilter(jwtService),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new RateLimitFilter(rateLimitRequestsPerMinute, Duration.ofMinutes(1)),
                        UsernamePasswordAuthenticationFilter.class);

        // formLogin only enabled when explicitly opted into via config —
        // never active by default, so a real consumer's app isn't silently
        // redirected to an HTML login page instead of getting a proper 401
        if (testUserEnabled) {
            http.formLogin(Customizer.withDefaults());
        }

        return http.build();
    }


    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");

        resolver.setAuthorizationRequestCustomizer(
                OAuth2AuthorizationRequestCustomizers.withPkce());

        return resolver;
    }



}