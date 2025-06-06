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
     * Gera uma senha forte com base nas preferências do usuário.
     *
     * @param length           Comprimento desejado da senha.
     * @param includeUppercase Incluir letras maiúsculas.
     * @param includeLowercase Incluir letras minúsculas.
     * @param includeNumbers   Incluir dígitos numéricos.
     * @param includeSymbols   Incluir símbolos especiais.
     * @return Senha gerada aleatoriamente, não presente em vazamentos conhecidos.
     */
    public static String generate(int length, boolean includeUppercase, boolean includeLowercase,
                                  boolean includeNumbers, boolean includeSymbols) {
        if (length <= 0) {
            throw new IllegalArgumentException("O comprimento da senha deve ser maior que zero.");
        }

        String characterPool = buildCharacterPool(includeUppercase, includeLowercase, includeNumbers, includeSymbols);

        if (characterPool.isEmpty()) {
            throw new IllegalArgumentException("Pelo menos um tipo de caractere deve ser selecionado.");
        }

        String password;
        int breachCount;

        do {
            password = generateRandomPassword(length, characterPool);
            breachCount = PasswordBreachChecker.checkPassword(password);

            if (breachCount > 0) {
                System.out.printf("Senha comprometida (%d vazamento(s)). Gerando outra...%n", breachCount);
            }

        } while (breachCount > 0);

        return password;
    }

    // Constrói o conjunto de caracteres permitido
    private static String buildCharacterPool(boolean includeUppercase, boolean includeLowercase,
                                             boolean includeNumbers, boolean includeSymbols) {
        StringBuilder pool = new StringBuilder();
        if (includeUppercase) pool.append(UPPERCASE);
        if (includeLowercase) pool.append(LOWERCASE);
        if (includeNumbers)   pool.append(NUMBERS);
        if (includeSymbols)   pool.append(SYMBOLS);
        return pool.toString();
    }

    // Gera uma senha aleatória com base na pool de caracteres
    private static String generateRandomPassword(int length, String characterPool) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characterPool.length());
            sb.append(characterPool.charAt(index));
        }
        return sb.toString();
    }
}
