package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;


public class OidcAuthStrategy implements AuthStrategy {

    /**
     * Same as OAuth2AuthStrategy — login is redirect-driven (/oauth2/authorization/google),
     * not credential-driven, so this is a no-op to satisfy the interface.
     */
    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        // Intentionally empty — see class Javadoc.
    }

    @Override
    public boolean isAuthenticated(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth instanceof OAuth2AuthenticationToken
                && auth.isAuthenticated()
                && auth.getPrincipal() instanceof OidcUser;
    }

    /**
     * Extracts the authenticated user's identity claims from the ID token.
     * Returns null if not authenticated via OIDC.
     */
    public OidcUser getCurrentOidcUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof OAuth2AuthenticationToken && auth.getPrincipal() instanceof OidcUser oidcUser) {
            return oidcUser;
        }
        return null;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        SecurityContextHolder.clearContext();
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
    }
}