package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class OAuth2AuthStrategy implements AuthStrategy {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RestTemplate restTemplate = new RestTemplate();

    public OAuth2AuthStrategy(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        // Intentionally empty — see class Javadoc.
    }

    @Override
    public boolean isAuthenticated(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth instanceof AbstractAuthenticationToken
                && auth.isAuthenticated()
                && auth.getPrincipal() instanceof OAuth2User;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth instanceof OAuth2AuthenticationToken oauthToken) {
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName()
            );

            if (client != null) {
                revokeGoogleToken(client.getAccessToken().getTokenValue());
            }
        }

        SecurityContextHolder.clearContext();
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
    }

    private void revokeGoogleToken(String accessToken) {
        try {
            String revokeUrl = "https://oauth2.googleapis.com/revoke?token=" + accessToken;
            restTemplate.postForEntity(revokeUrl, null, String.class);
        } catch (Exception e) {
            // Revocation failing shouldn't block local logout — log and continue
        }
    }
}