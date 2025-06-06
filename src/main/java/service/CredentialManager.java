package service;

import model.Credential;
import utils.InputSanitizer;
import utils.PasswordGenerator;
import org.mindrot.jbcrypt.BCrypt;

import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.awt.Toolkit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.IntStream;

public class CredentialManager {

    private final List<Credential> credentials;
    private final Scanner scanner;

    public CredentialManager(List<Credential> credentials) {
        this.credentials = credentials;
        this.scanner = new Scanner(System.in);
    }

    public void showMenu() {
        Map<String, Runnable> actions = new HashMap<>();
        actions.put("1", this::listCredentials);
        actions.put("2", this::addCredential);
        actions.put("3", this::removeCredential);
        actions.put("4", this::copyPasswordToClipboard);
        actions.put("5", this::checkCompromisedPasswords);
        actions.put("6", this::saveAndExit);

        while (true) {
            System.out.println("\n=== Gerenciador de Credenciais ===");
            System.out.println("1. Listar todas as credenciais");
            System.out.println("2. Adicionar nova credencial");
            System.out.println("3. Remover uma credencial");
            System.out.println("4. Copiar senha para a área de transferência");
            System.out.println("5. Verificar senhas comprometidas");
            System.out.println("6. Sair");
            System.out.print("Escolha uma opção: ");

            String option = scanner.nextLine();
            Runnable action = actions.get(option);
            if (action != null) {
                action.run();
                if ("6".equals(option)) break;
            } else {
                System.out.println("Opção inválida. Tente novamente.");
            }
        }
    }

    private void listCredentials() {
        if (credentials.isEmpty()) {
            System.out.println("Nenhuma credencial armazenada.");
            return;
        }

        IntStream.range(0, credentials.size())
            .mapToObj(i -> String.format("%d. Serviço: %s | Usuário: %s", i + 1,
                    credentials.get(i).serviceName(), credentials.get(i).username()))
            .forEach(System.out::println);
    }

    private void addCredential() {
        try {
            String service = prompt("Digite o nome do serviço:", 50, false);
            String username = prompt("Digite o nome de usuário:", 50, false);
            String option = promptYesNo("Gerar uma senha forte? (s/n):");

            String password = option.equals("s") ? generateCustomPassword() : prompt("Digite a senha:", 64, false);
            String encrypted = EncryptionService.encrypt(password);

            credentials.add(new Credential(service, username, encrypted));
            System.out.println("Credencial adicionada com sucesso.");
        } catch (Exception e) {
            System.err.println("Erro ao adicionar credencial: " + e.getMessage());
        }
    }

    private String generateCustomPassword() {
        int length = askPasswordLength();
        boolean upper = askInclude("Incluir letras maiúsculas?");
        boolean lower = askInclude("Incluir letras minúsculas?");
        boolean digits = askInclude("Incluir números?");
        boolean symbols = askInclude("Incluir símbolos?");

        if (!(upper || lower || digits || symbols)) {
            throw new IllegalArgumentException("Pelo menos um tipo de caractere deve ser selecionado.");
        }

        return PasswordGenerator.generate(length, upper, lower, digits, symbols);
    }

    private void removeCredential() {
        listCredentials();
        if (credentials.isEmpty()) return;

        int index = getIndex("Digite o número da credencial para remover:") - 1;
        if (isValidIndex(index)) {
            Credential removed = credentials.remove(index);
            System.out.println("Removido: " + removed.serviceName());
        } else {
            System.out.println("Índice inválido.");
        }
    }

    private void copyPasswordToClipboard() {
        if (credentials.isEmpty()) {
            System.out.println("Nenhuma credencial armazenada.");
            return;
        }

        listCredentials();
        int index = getIndex("Digite o número da credencial para copiar a senha:") - 1;
        if (!isValidIndex(index)) {
            System.out.println("Índice inválido.");
            return;
        }

        System.out.print("Digite novamente a senha mestre para confirmar: ");
        String inputPassword = scanner.nextLine().trim();

        Optional<String> storedHash = readMasterPasswordHash();
        if (storedHash.isEmpty() || !BCrypt.checkpw(inputPassword, storedHash.get())) {
            System.out.println("Senha mestre incorreta ou não configurada.");
            return;
        }

        try {
            String decrypted = EncryptionService.decrypt(credentials.get(index).encryptedPassword());
            copyToClipboard(decrypted);
            System.out.printf("Senha para %s copiada para a área de transferência.%n",
                    credentials.get(index).serviceName());
        } catch (Exception e) {
            System.err.println("Erro ao copiar senha: " + e.getMessage());
        }
    }

    private void checkCompromisedPasswords() {
        if (credentials.isEmpty()) {
            System.out.println("Nenhuma credencial armazenada.");
            return;
        }

        boolean anyCompromised = false;
        System.out.println("Verificando senhas comprometidas...");

        for (Credential c : credentials) {
            try {
                String decrypted = EncryptionService.decrypt(c.encryptedPassword());
                int count = PasswordBreachChecker.checkPassword(decrypted);
                if (count > 0) {
                    System.out.printf("⚠️  Serviço: '%s' | Usuário: '%s' - Apareceu em %d vazamentos.%n",
                            c.serviceName(), c.username(), count);
                    anyCompromised = true;
                }
            } catch (Exception e) {
                System.err.printf("Erro com '%s': %s%n", c.serviceName(), e.getMessage());
            }
        }

        if (!anyCompromised) {
            System.out.println("Nenhuma senha comprometida encontrada.");
        }
    }

    private void saveAndExit() {
        try {
            CredentialStorage.saveCredentials(credentials);
            System.out.println("Credenciais salvas. Encerrando...");
        } catch (Exception e) {
            System.err.println("Erro ao salvar as credenciais: " + e.getMessage());
        }
    }

    // ========== Métodos Utilitários ==========
    private String prompt(String message, int maxLength, boolean numbersOnly) {
        System.out.print(message + " ");
        return InputSanitizer.sanitize(scanner.nextLine(), maxLength, numbersOnly);
    }

    private String promptYesNo(String message) {
        while (true) {
            System.out.print(message + " ");
            String input = scanner.nextLine().toLowerCase();
            if (input.equals("s") || input.equals("n")) return input;
            System.out.println("Entrada inválida. Digite 's' ou 'n'.");
        }
    }

    private boolean askInclude(String message) {
        return promptYesNo(message + " (s/n):").equals("s");
    }

    private int askPasswordLength() {
        while (true) {
            System.out.print("Comprimento da senha (mínimo 8): ");
            try {
                int length = Integer.parseInt(scanner.nextLine());
                if (length >= 8) return length;
                System.out.println("A senha deve ter pelo menos 8 caracteres.");
            } catch (NumberFormatException e) {
                System.out.println("Digite um número válido.");
            }
        }
    }

    private int getIndex(String message) {
        System.out.print(message + " ");
        try {
            return Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private boolean isValidIndex(int index) {
        return index >= 0 && index < credentials.size();
    }

    private Optional<String> readMasterPasswordHash() {
        try {
            Path path = Path.of("master_password.dat");
            if (!Files.exists(path)) return Optional.empty();
            return Optional.of(Files.readString(path).trim());
        } catch (IOException e) {
            System.err.println("Erro ao ler a senha mestre: " + e.getMessage());
            return Optional.empty();
        }
    }

    private void copyToClipboard(String text) {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(text), null);
        } catch (Exception e) {
            System.err.println("Erro ao copiar para a área de transferência: " + e.getMessage());
        }
    }
}
