package service;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

public class TOTPService {
    private static final long TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final String SECRET_FILE = "totp_secret.dat";

    // === Chave Secreta ===

    public static String generateSecret() {
        byte[] bytes = new byte[20]; // 160 bits
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String getBase32Secret(String base64Secret) {
        Base32 base32 = new Base32();
        byte[] decoded = Base64.getDecoder().decode(base64Secret);
        return base32.encodeToString(decoded).replace("=", "").replace(" ", "");
    }

    public static String getOtpAuthUrl(String base64Secret, String accountName, String issuer) {
        String base32Secret = getBase32Secret(base64Secret);
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer, accountName, base32Secret, issuer);
    }

    public static String loadOrCreateSecret() {
        Path path = Paths.get(SECRET_FILE);

        if (Files.exists(path)) {
            try {
                String secret = Files.readString(path).trim();
                if (!secret.isEmpty()) return secret;
            } catch (IOException e) {
                System.err.println("Erro ao ler segredo: " + e.getMessage());
            }
        }

        String newSecret = generateSecret();
        try {
            Files.writeString(path, newSecret);
        } catch (IOException e) {
            System.err.println("Erro ao salvar segredo: " + e.getMessage());
        }
        return newSecret;
    }

    // === Validação de Código TOTP ===

    public static boolean validateCode(String base64Secret, String inputCode) {
        if (!isValidCode(inputCode)) return false;

        long currentWindow = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;

        try {
            for (long offset = -1; offset <= 1; offset++) {
                if (generateCodeAtTime(base64Secret, currentWindow + offset).equals(inputCode)) {
                    return true;
                }
            }
        } catch (Exception e) {
            System.err.println("Erro na validação TOTP: " + e.getMessage());
        }

        System.out.println("Código inválido. Tente novamente.");
        return false;
    }

    private static boolean isValidCode(String code) {
        if (code == null || code.length() != CODE_DIGITS) {
            System.out.printf("Código deve conter exatamente %d dígitos.%n", CODE_DIGITS);
            return false;
        }
        if (!code.matches("\\d{" + CODE_DIGITS + "}")) {
            System.out.println("Código deve conter apenas dígitos numéricos.");
            return false;
        }
        return true;
    }

    private static String generateCodeAtTime(String base64Secret, long timeWindow) throws Exception {
        byte[] key = Base64.getDecoder().decode(base64Secret);
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (timeWindow & 0xFF);
            timeWindow >>= 8;
        }

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        byte[] hmac = mac.doFinal(data);

        int offset = hmac[hmac.length - 1] & 0xF;
        int binary =
                ((hmac[offset] & 0x7F) << 24) |
                ((hmac[offset + 1] & 0xFF) << 16) |
                ((hmac[offset + 2] & 0xFF) << 8) |
                (hmac[offset + 3] & 0xFF);

        int otp = binary % (int) Math.pow(10, CODE_DIGITS);
        return String.format("%0" + CODE_DIGITS + "d", otp);
    }
}
