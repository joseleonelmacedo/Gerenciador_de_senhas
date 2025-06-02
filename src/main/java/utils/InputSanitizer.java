package utils;

public class InputSanitizer {
    /**
     * Construtor privado para evitar instanciamento.
     */
    private InputSanitizer() {
        // Classe utilitária, não deve ser instanciada
    }

    /**
     * Sanitiza a entrada fornecida pelo usuário para prevenir possíveis ataques de injeção.
     *
     * @param input           A entrada bruta do usuário.
     * @param maxLength       O comprimento máximo permitido da entrada.
     * @param numericOnly     Se deve permitir apenas números.
     * @return A entrada do usuário sanitizada e segura.
     * @throws IllegalArgumentException Se a entrada for nula, inválida ou insegura.
     */
    public static String sanitize(String input, int maxLength, boolean numericOnly) throws IllegalArgumentException {
        if (input == null) {
            throw new IllegalArgumentException("A entrada não pode ser nula.");
        }
        input = input.trim();
        if (input.isEmpty() || input.length() > maxLength) {
            throw new IllegalArgumentException("A entrada é inválida ou excede o comprimento permitido.");
        }
        if (numericOnly && !input.matches("\\d+")) {
            throw new IllegalArgumentException("A entrada deve conter apenas caracteres numéricos.");
        }
        if (!numericOnly && (
                input.indexOf(';') >= 0 || 
                input.indexOf('\'') >= 0 ||
                input.indexOf('"') >= 0 ||
                input.indexOf('<') >= 0 ||
                input.indexOf('>') >= 0 ||
                input.indexOf(',') >= 0)) {
            throw new IllegalArgumentException("A entrada contém caracteres inseguros.");
        }
        return input;
    }

    /**
     * Escapa entradas potencialmente inseguras para registro seguro (log).
     *
     * @param input A entrada fornecida pelo usuário.
     * @return Entrada com caracteres inseguros escapados.
     */
    public static String escapeForLog(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
