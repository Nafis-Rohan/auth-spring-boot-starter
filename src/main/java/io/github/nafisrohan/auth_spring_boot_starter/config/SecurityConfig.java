package io.github.nafisrohan.auth_spring_boot_starter.config;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.filter.JwtAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.filter.SessionAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
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


@Configuration
public class SecurityConfig {

    private final SessionAuthStrategy sessionAuthStrategy;
    private final JwtService jwtService;

    public SecurityConfig(SessionAuthStrategy sessionAuthStrategy, JwtService jwtService) {
        this.sessionAuthStrategy = sessionAuthStrategy;
        this.jwtService = jwtService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//Store the CSRF token in a cookie
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())///This tells Spring how to look for/use the CSRF token from incoming requests.
                        .ignoringRequestMatchers("/auth/jwt/**") // JWT uses Authorization header, not cookies — CSRF doesn't apply
                )
                .authorizeHttpRequests(auth -> auth
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
                        .rpId("localhost") //Which website is allowed to use this passkey? So the passkey is associated with localhost.
                        .allowedOrigins("http://localhost:8080") //WebAuthn will accept authentication requests originating from http://localhost:8080.
                )
                .formLogin(Customizer.withDefaults())
                .addFilterBefore(new SessionAuthFilter(sessionAuthStrategy),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthFilter(jwtService),
                        UsernamePasswordAuthenticationFilter.class);
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


    //webAuth
    @Bean //Create this object and manage it in the Spring container
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder() //Creates a builder for creating a Spring Security user.
                .username("nafis")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}