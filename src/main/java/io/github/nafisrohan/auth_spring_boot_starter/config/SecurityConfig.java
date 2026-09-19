package io.github.nafisrohan.auth_spring_boot_starter.config;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.filter.JwtAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.filter.RateLimitFilter;
import io.github.nafisrohan.auth_spring_boot_starter.filter.SessionAuthFilter;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
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

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;


import org.springframework.security.web.authentication.HttpStatusEntryPoint;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.time.Duration;


@AutoConfiguration
@EnableMethodSecurity //Turn on security checks on individual methods.
public class SecurityConfig {


    @Value("${webauthn.rp-id:localhost}")
    private String webAuthnRpId;

    @Value("${webauthn.allowed-origins:http://localhost:8080}")
    private String webAuthnAllowedOrigin;

    @Value("${rate-limit.requests-per-minute:5}")
    private int rateLimitRequestsPerMinute;

    @Value("${rate-limit.window-seconds:60}")
    private int rateLimitWindowSeconds;


    private final SessionAuthStrategy sessionAuthStrategy;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(SessionAuthStrategy sessionAuthStrategy, JwtService jwtService ,UserDetailsService userDetailsService) {
        this.sessionAuthStrategy = sessionAuthStrategy;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   @org.springframework.beans.factory.annotation.Autowired(required = false)
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   @Value("${unifyauth.test-user.enabled:false}") boolean testUserEnabled) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//Store the CSRF token in a cookie
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())///This tells Spring how to look for/use the CSRF token from incoming requests.
                        .ignoringRequestMatchers(request -> {
                            // Exempt any request carrying a Bearer token from CSRF, regardless
                            // of URL — JWT uses the Authorization header, not cookies, so it
                            // isn't vulnerable to CSRF at all.
                            String authHeader = request.getHeader("Authorization");
                            return authHeader != null && authHeader.startsWith("Bearer ");
                        })
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/mfa/**").authenticated()
                        .requestMatchers("/auth/**", "/jwt/**", "/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                (request, response, authException) -> {
                                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                                    response.setContentType("text/plain");
                                    response.getWriter().write("Unauthorized — please log in");
                                },
                                PathPatternRequestMatcher.withDefaults().matcher("/**")
                        )
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType("text/plain");
                            response.getWriter().write("Access denied");
                        })
                )
                //webAuthn Enables/configures WebAuthn in Spring Security.
                .webAuthn(webAuthn -> webAuthn
                        .rpId(webAuthnRpId) //Which website is allowed to use this passkey? So the passkey is associated with localhost.
                        .allowedOrigins(webAuthnAllowedOrigin) //WebAuthn will accept authentication requests originating from http://localhost:8080.
                )
                .addFilterBefore(new SessionAuthFilter(sessionAuthStrategy),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new RateLimitFilter(rateLimitRequestsPerMinute, Duration.ofSeconds(rateLimitWindowSeconds)),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthFilter(jwtService, userDetailsService),
                        UsernamePasswordAuthenticationFilter.class);

        // OAuth2 login only configured if a ClientRegistrationRepository bean
        // actually exists — a consumer who hasn't set up OAuth2 (no client-id/
        // secret in their own application.yml) shouldn't be forced to have it,
        // same reasoning as making formLogin opt-in below
        if (clientRegistrationRepository != null) {
            http.oauth2Login(oauth2 -> oauth2
                    .defaultSuccessUrl("/auth/oauth2/success", true)
                    .authorizationEndpoint(endpoint -> endpoint
                            .authorizationRequestResolver(authorizationRequestResolver(clientRegistrationRepository))
                    )
            );
        }

        // formLogin only enabled when explicitly opted into via config —
        // never active by default, so a real consumer's app isn't silently
        // redirected to an HTML login page instead of getting a proper 401
        if (testUserEnabled) {
            http.formLogin(Customizer.withDefaults());
        }

        return http.build();
    }




    @Bean
    @ConditionalOnBean(ClientRegistrationRepository.class)
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