package utils;

public class PasswordStrengthEvaluator {

    /**
     * Verifica se uma senha atende aos critérios mínimos de segurança:
     * - Pelo menos 8 caracteres
     * - Pelo menos uma letra maiúscula
     * - Pelo menos uma letra minúscula
     * - Pelo menos um número
     * - Pelo menos um símbolo
     */
    public static boolean isStrong(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSymbol = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (isSymbol(c)) {
                hasSymbol = true;
            }
        }

        return hasUpper && hasLower && hasDigit && hasSymbol;
    }

    private static boolean isSymbol(char c) {
        // Qualquer caractere que não seja letra nem número
        return !Character.isLetterOrDigit(c);
    }
}
