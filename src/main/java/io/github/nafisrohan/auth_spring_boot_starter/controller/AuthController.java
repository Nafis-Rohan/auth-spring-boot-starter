package io.github.nafisrohan.auth_spring_boot_starter.controller;

import io.github.nafisrohan.auth_spring_boot_starter.config.AuthProperties;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.JwtAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.OidcAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.OAuth2AuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.mfa.TotpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.core.Authentication;

import org.springframework.security.web.csrf.CsrfToken;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final SessionAuthStrategy sessionAuthStrategy;
    private final JwtAuthStrategy jwtAuthStrategy;
    private final OidcAuthStrategy  oidcAuthStrategy;
    private final OAuth2AuthStrategy  oAuth2AuthStrategy;
    private final TotpService totpService;
    private final AuthProperties authProperties;



    public AuthController(SessionAuthStrategy sessionAuthStrategy,
                          JwtAuthStrategy jwtAuthStrategy,
                          OidcAuthStrategy oidcAuthStrategy,
                          OAuth2AuthStrategy oAuth2AuthStrategy,
                          TotpService totpService,
                          AuthProperties authProperties) {
        this.sessionAuthStrategy = sessionAuthStrategy;
        this.jwtAuthStrategy = jwtAuthStrategy;
        this.oidcAuthStrategy = oidcAuthStrategy;
        this.oAuth2AuthStrategy = oAuth2AuthStrategy;
        this.totpService = totpService;
        this.authProperties = authProperties;
    }


    /**============================= Cookie based =========================================**/

//    @PostMapping("/login")
//    public String login(@RequestParam String username, @RequestParam String password,
//                        HttpServletRequest request, HttpServletResponse response) {
//        sessionAuthStrategy.login(request, response, username, password);
//        return "Logged in as " + username;
//    }

    @GetMapping("/check")
    public String check(HttpServletRequest request) {
        boolean authenticated = sessionAuthStrategy.isAuthenticated(request);
        return authenticated ? "You are authenticated" : "You are NOT authenticated";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        sessionAuthStrategy.logout(request, response);
        return "Logged out";
    }


    /**============================= jwt based =========================================**/
//    @PostMapping("/jwt/login")
//    public String jwtLogin(@RequestParam String username, @RequestParam String password,
//                           HttpServletRequest request, HttpServletResponse response) {
//        jwtAuthStrategy.login(request, response, username, password);
//        return "Logged in as " + username + " — check the Authorization header for your token";
//    }

    @GetMapping("/jwt/check")
    public String jwtCheck(HttpServletRequest request) {
        boolean authenticated = jwtAuthStrategy.isAuthenticated(request);
        return authenticated ? "You are authenticated (JWT)" : "You are NOT authenticated (JWT)";
    }

    @PostMapping("/jwt/refresh")
    public String jwtRefresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = request.getHeader("X-Refresh-Token");

        if (refreshToken == null || !jwtAuthStrategy.isRefreshTokenValid(refreshToken)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return "Invalid or missing refresh token";
        }

        String username = jwtAuthStrategy.getUsernameFromRefreshToken(refreshToken);
        String newAccessToken = jwtAuthStrategy.generateNewAccessToken(username);
        response.setHeader("Authorization", "Bearer " + newAccessToken);
        return "New access token issued";
    }

    @PostMapping("/jwt/logout")
    public String jwtLogout(HttpServletRequest request, HttpServletResponse response) {
        jwtAuthStrategy.logout(request, response);
        return "Logged out (JWT)";
    }



    /**============================= OAuth 2=========================================**/
    //@AuthenticationPrincipal = Give me the currently logged-in user's information
    // principal storing authenticated OAuth2 user
    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not authenticated");
        }
        return ResponseEntity.ok(principal.getAttributes());
    }

    @PostMapping("/oauth2/logout")
    public ResponseEntity<String> oauth2Logout(HttpServletRequest request, HttpServletResponse response) {
        if (oAuth2AuthStrategy == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body("OAuth2 is not configured for this application");
        }
        boolean revoked = oAuth2AuthStrategy.revokeAndLogout(request, response);
        return ResponseEntity.ok(revoked
                ? "Logged out (OAuth2) — token revoked at Google"
                : "Logged out locally (OAuth2) — token revocation at Google failed or was not attempted");
    }


    /**============================= OIDC =========================================**/
    @GetMapping("/oidc/identity")
    public ResponseEntity<?> oidcIdentity() {
        OidcUser user = oidcAuthStrategy.getCurrentOidcUser();
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not authenticated via OIDC");
        }

        Map<String, Object> identity = new HashMap<>();
        identity.put("subject", user.getSubject());
        identity.put("email", user.getEmail());
        identity.put("name", user.getFullName());
        identity.put("picture", user.getPicture());

        return ResponseEntity.ok(identity);
    }

    /**============================= MFA / TOTP =========================================**/

    private final java.util.concurrent.ConcurrentHashMap<String, Object> enrollmentLocks =
            new java.util.concurrent.ConcurrentHashMap<>();
    @PostMapping("/mfa/enable")
    public ResponseEntity<String> enableMfa(Authentication authentication) {
        String username = authentication.getName();
        Object lock = enrollmentLocks.computeIfAbsent(username, k -> new Object());

        synchronized (lock) {
            String secret = totpService.generateSecret();
            String qrCodeUri;
            try {
                qrCodeUri = totpService.generateQrCodeImageUri(username, secret);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Failed to generate QR code — MFA not enabled");
            }
            totpService.saveSecretForUser(username, secret);
            return ResponseEntity.ok(qrCodeUri);
        }
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<String> verifyMfa(Authentication authentication, @RequestParam String code) {
        String username = authentication.getName();
        String secret = totpService.getSecretForUser(username);
        if (secret == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("MFA not enabled for this user");
        }
        boolean valid = totpService.verifyCode(secret, code);
        return valid
                ? ResponseEntity.ok("Code valid — MFA verified")
                : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Code invalid");
    }



    @GetMapping("/csrf-token")
    public String getCsrfToken(HttpServletRequest request) {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            csrfToken.getToken(); // forces Spring to resolve and write the cookie
        }
        return "CSRF cookie has been set — check your cookies for XSRF-TOKEN";
    }








    // Cookie and jwt
    @PostMapping("/unified-login")
    public ResponseEntity<String> unifiedLogin(@RequestParam String username, @RequestParam String password,
                                               HttpServletRequest request, HttpServletResponse response) {
        String strategy = authProperties.getStrategy();

        switch (strategy) {
            case "session" -> {
                sessionAuthStrategy.login(request, response, username, password);
                return ResponseEntity.ok("Logged in as " + username + " (session)");
            }
            case "jwt" -> {
                jwtAuthStrategy.login(request, response, username, password);
                return ResponseEntity.ok("Logged in as " + username + " (JWT — check Authorization header)");
            }
            default -> {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Unsupported or misconfigured strategy: " + strategy);
            }
        }
    }


}