package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthStrategy implements AuthStrategy {

    private final JwtService jwtService;

    public JwtAuthStrategy(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        // TODO: no real credential check yet — same gap as SessionAuthStrategy
        String accessToken = jwtService.generateAccessToken(username);
        String refreshToken = jwtService.generateRefreshToken(username);

        response.setHeader("Authorization", "Bearer " + accessToken);
        response.setHeader("X-Refresh-Token", refreshToken);
    }

    @Override
    public boolean isAuthenticated(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7); // remove "Bearer " prefix
        return jwtService.isTokenValid(token);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);
            jwtService.blacklistToken(accessToken);
        }

        String refreshToken = request.getHeader("X-Refresh-Token");
        if (refreshToken != null) {
            jwtService.blacklistToken(refreshToken);
        }
    }


    public boolean isRefreshTokenValid(String refreshToken) {
        return jwtService.isTokenValid(refreshToken) && jwtService.isRefreshToken(refreshToken);
    }

    public String getUsernameFromRefreshToken(String refreshToken) {
        return jwtService.extractUsername(refreshToken);
    }

    public String generateNewAccessToken(String username) {
        return jwtService.generateAccessToken(username);
    }
}