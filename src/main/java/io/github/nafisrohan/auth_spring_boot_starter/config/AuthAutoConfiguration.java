package io.github.nafisrohan.auth_spring_boot_starter.config;

import io.github.nafisrohan.auth_spring_boot_starter.controller.TestController;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.JwtAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.OAuth2AuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.OidcAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
import io.github.nafisrohan.auth_spring_boot_starter.mfa.TotpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import io.github.nafisrohan.auth_spring_boot_starter.controller.AuthController;

import io.github.nafisrohan.auth_spring_boot_starter.exception.GlobalExceptionHandler;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {

    @Bean
    public SessionAuthStrategy sessionAuthStrategy(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        return new SessionAuthStrategy(userDetailsService, passwordEncoder);
    }

    @Bean
    public JwtAuthStrategy jwtAuthStrategy(JwtService jwtService, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        return new JwtAuthStrategy(jwtService, userDetailsService, passwordEncoder);
    }

    @Bean
    @ConditionalOnBean(OAuth2AuthorizedClientService.class)
    public OAuth2AuthStrategy oAuth2AuthStrategy(OAuth2AuthorizedClientService authorizedClientService) {
        return new OAuth2AuthStrategy(authorizedClientService);
    }

    @Bean
    public OidcAuthStrategy oidcAuthStrategy() {
        return new OidcAuthStrategy();
    }

    @Bean
    public TotpService totpService() {
        return new TotpService();
    }

    @Bean
    public JwtService jwtService() {
        return new JwtService();
    }




    @Bean
    public AuthController authController(SessionAuthStrategy sessionAuthStrategy,
                                         JwtAuthStrategy jwtAuthStrategy,
                                         OidcAuthStrategy oidcAuthStrategy,
                                         @Autowired(required = false) OAuth2AuthStrategy oAuth2AuthStrategy,
                                         TotpService totpService,
                                         AuthProperties authProperties) {
        return new AuthController(sessionAuthStrategy, jwtAuthStrategy, oidcAuthStrategy,
                oAuth2AuthStrategy, totpService, authProperties);
    }



    @Bean
    public GlobalExceptionHandler globalExceptionHandler() {
        return new GlobalExceptionHandler();
    }


    @Bean
    @ConditionalOnProperty(name = "unifyauth.test-user.enabled", havingValue = "true")
    public TestController testController() {
        return new TestController();
    }
}