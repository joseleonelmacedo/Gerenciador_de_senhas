package utils;

import service.PasswordBreachChecker;
import java.security.SecureRandom;

public class PasswordGenerator {
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUMBERS = "0123456789";
    private static final String SYMBOLS = "!@#$%&*()-_=+[]{}";
    private static final SecureRandom random = new SecureRandom();

    /**
     * Gera uma senha forte baseada nas preferências do usuário.
     *
     * @param length           O comprimento da senha gerada.
     * @param includeUppercase Se deve incluir letras maiúsculas.
     * @param includeLowercase Se deve incluir letras minúsculas.
     * @param includeNumbers   Se deve incluir dígitos numéricos.
     * @param includeSymbols   Se deve incluir caracteres especiais.
     * @return Uma senha gerada aleatoriamente como String.
     */
    public static String generate(int length, boolean includeUppercase, boolean includeLowercase,
                                  boolean includeNumbers, boolean includeSymbols) {
        StringBuilder characterPool = new StringBuilder();
        if (includeUppercase) characterPool.append(UPPERCASE);
        if (includeLowercase) characterPool.append(LOWERCASE);
        if (includeNumbers) characterPool.append(NUMBERS);
        if (includeSymbols) characterPool.append(SYMBOLS);

        if (characterPool.isEmpty() || length <= 0) {
            throw new IllegalArgumentException("Parâmetros inválidos para geração de senha.");
        }

        String password;
        int breachCount;
        do {
            StringBuilder passwordBuilder = new StringBuilder(length);
            for (int i = 0; i < length; i++) {
                int index = random.nextInt(characterPool.length());
                passwordBuilder.append(characterPool.charAt(index));
            }
            password = passwordBuilder.toString();
            
            // Verifica se a senha foi encontrada em vazamentos usando PasswordBreachChecker
            breachCount = PasswordBreachChecker.checkPassword(password);

            if (breachCount > 0) {
                System.out.printf("Senha gerada foi encontrada em %d vazamento(s). Gerando uma senha mais segura...%n", breachCount);
            }
        } while (breachCount > 0); // Regenera se a senha estiver comprometida

        return password;
    }
}
