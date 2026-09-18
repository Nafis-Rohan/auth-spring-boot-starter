package io.github.nafisrohan.auth_spring_boot_starter.core.strategies;

import io.github.nafisrohan.auth_spring_boot_starter.core.AuthStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthStrategy implements AuthStrategy {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public JwtAuthStrategy(JwtService jwtService, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void login(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        // Real credential check — same pattern as SessionAuthStrategy,
        // closes the "same gap as SessionAuthStrategy" TODO that was here.
        UserDetails storedUser = userDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, storedUser.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

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