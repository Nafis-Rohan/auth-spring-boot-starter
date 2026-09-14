package io.github.nafisrohan.auth_spring_boot_starter.jwt.signing;

public interface JwtSigningStrategy {
    String sign(String username, long expiryMillis, String tokenType);
    boolean verify(String token);
    String extractUsername(String token);
    long extractExpiry(String token);
    String extractTokenType(String token);
}