package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

@Component
public class OAuth2AuthStrategy implements AuthStrategy {

    /**
     * OAuth2 login doesn't take username/password directly — the user is
     * authenticated by redirecting to /oauth2/authorization/google, handled
     * entirely by Spring Security's oauth2Login() filter chain. This method
     * exists only to satisfy the AuthStrategy contract; it's a no-op here.
     */
    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        // Intentionally empty — see class Javadoc.
    }

    @Override
    public boolean isAuthenticated(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth instanceof AbstractAuthenticationToken
                && auth.isAuthenticated()
                && auth.getPrincipal() instanceof OidcUser;
    }

    /**
     * Spring Security's default OAuth2 logout just clears the local
     * session/SecurityContext — it does not revoke the token at Google.
     * That's a reasonable default for now; true provider-side revocation
     * is a possible future improvement, not needed for today's scope.
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        SecurityContextHolder.clearContext();
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
    }
}