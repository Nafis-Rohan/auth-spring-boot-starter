package io.github.nafisrohan.auth_spring_boot_starter.mfa;

import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import org.springframework.stereotype.Service;
import dev.samstevens.totp.code.CodeVerifier;


import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import java.util.Base64;

@Service
public class TotpService {

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(new DefaultCodeGenerator(), timeProvider);
    private final java.util.Map<String, String> userSecrets = new java.util.concurrent.ConcurrentHashMap<>();// username → secret

    public String generateSecret() {
        return secretGenerator.generate();
    }

    public String generateQrCodeImageUri(String username, String secret) {
        QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer("AuthSpringBootStarter")
                .algorithm(dev.samstevens.totp.code.HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        try {
            byte[] imageData = qrGenerator.generate(data);
            String base64 = Base64.getEncoder().encodeToString(imageData);
            return "data:image/png;base64," + base64;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }

    public void saveSecretForUser(String username, String secret) {
        userSecrets.put(username, secret);
    }

    public String getSecretForUser(String username) {
        return userSecrets.get(username);
    }

    //Check whether MFA is enabled
    public boolean isMfaEnabled(String username) {
        return userSecrets.containsKey(username);
    }
}