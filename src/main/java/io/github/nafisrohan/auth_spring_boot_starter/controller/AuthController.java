package io.github.nafisrohan.auth_spring_boot_starter.controller;

import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.JwtAuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.core.strategies.SessionAuthStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final SessionAuthStrategy sessionAuthStrategy;
    private final JwtAuthStrategy jwtAuthStrategy;

    public AuthController(SessionAuthStrategy sessionAuthStrategy,
                          JwtAuthStrategy jwtAuthStrategy) {

        this.sessionAuthStrategy = sessionAuthStrategy;
        this.jwtAuthStrategy = jwtAuthStrategy;
    }




    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpServletRequest request, HttpServletResponse response) {
        sessionAuthStrategy.login(request, response, username, password);
        return "Logged in as " + username;
    }

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

    @GetMapping("/csrf-token")
    public String getCsrfToken() {
        return "CSRF cookie has been set — check your cookies for XSRF-TOKEN";
    }



    /**============================= jwt based =========================================**/
    @PostMapping("/jwt/login")
    public String jwtLogin(@RequestParam String username, @RequestParam String password,
                           HttpServletRequest request, HttpServletResponse response) {
        jwtAuthStrategy.login(request, response, username, password);
        return "Logged in as " + username + " — check the Authorization header for your token";
    }

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
}