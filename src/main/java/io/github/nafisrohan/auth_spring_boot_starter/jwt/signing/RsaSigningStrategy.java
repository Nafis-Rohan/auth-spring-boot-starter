package io.github.nafisrohan.auth_spring_boot_starter.jwt.signing;

import io.jsonwebtoken.Jwts;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class RsaSigningStrategy implements JwtSigningStrategy {

    private final KeyPair keyPair;

    public RsaSigningStrategy() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    @Override
    public String sign(String username, long expiryMillis, String tokenType) {
        return Jwts.builder()
                .subject(username)
                .claim("type", tokenType)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiryMillis))
                .signWith(keyPair.getPrivate())
                .compact();
    }

    @Override
    public boolean verify(String token) {
        try {
            Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String extractUsername(String token) {
        return Jwts.parser().verifyWith(keyPair.getPublic()).build()
                .parseSignedClaims(token).getPayload().getSubject();
    }

    @Override
    public long extractExpiry(String token) {
        return Jwts.parser().verifyWith(keyPair.getPublic()).build()
                .parseSignedClaims(token).getPayload().getExpiration().getTime();
    }

    @Override
    public String extractTokenType(String token) {
        return Jwts.parser().verifyWith(keyPair.getPublic()).build()
                .parseSignedClaims(token).getPayload().get("type", String.class);
    }
}