package io.github.nafisrohan.auth_spring_boot_starter.jwt;

import io.github.nafisrohan.auth_spring_boot_starter.jwt.signing.HmacSigningStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.signing.JwtSigningStrategy;
import io.github.nafisrohan.auth_spring_boot_starter.jwt.signing.RsaSigningStrategy;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.algorithm:HS256}")
    private String algorithm;

    @Value("${jwt.access-token-expiry}")
    private long accessTokenExpiry;


    @Value("${jwt.refresh-token-expiry}")
    private long refreshTokenExpiry;


    private JwtSigningStrategy signingStrategy;
    //A collection that stores unique strings: blocklist
    private final java.util.Map<String, Long> blocklist = new java.util.concurrent.ConcurrentHashMap<>();

    @PostConstruct //Run this method automatically once, after Spring creates this object and injects its configuration values.
    private void init() {
        if ("RS256".equalsIgnoreCase(algorithm)) {
            this.signingStrategy = new RsaSigningStrategy();
        } else if ("HS256".equalsIgnoreCase(algorithm)) {
            this.signingStrategy = new HmacSigningStrategy(secret);
        } else {
            throw new IllegalStateException(
                    "Invalid jwt.algorithm value: '" + algorithm + "'. Supported values are HS256 and RS256.");
        }
    }

    public String generateAccessToken(String username) {
        return signingStrategy.sign(username, accessTokenExpiry, "access");
    }

    public String generateRefreshToken(String username) {
        return signingStrategy.sign(username, refreshTokenExpiry, "refresh");
    }

    public String extractUsername(String token) {
        return signingStrategy.extractUsername(token);
    }

    public boolean isTokenValid(String token) {
        if (isBlacklisted(token)) {
            return false;
        }
        return signingStrategy.verify(token);
    }

    public void blacklistToken(String token) {
        try {
            long tokenExpiry = signingStrategy.extractExpiry(token);
            blocklist.put(token, tokenExpiry);
        } catch (Exception e) {
            // Token is already malformed/expired — nothing meaningful to revoke,
            // treat logout as already complete rather than failing the request
        }
    }

    public boolean isBlacklisted(String token) {
        Long expiry = blocklist.get(token);
        if (expiry == null) {
            return false;
        }
        if (System.currentTimeMillis() > expiry) {
            blocklist.remove(token); // expired anyway, safe to clean up
            return false;
        }
        return true;
    }

    public boolean isRefreshToken(String token) {
        return "refresh".equals(signingStrategy.extractTokenType(token));
    }


}