package service;

import utils.InputSanitizer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.regex.Pattern;

import org.mindrot.jbcrypt.BCrypt;

/**
 * Classe responsável pela autenticação segura do usuário utilizando senha mestre e TOTP.
 */
public class AuthService {

    private static final String PASSWORD_FILE = "master_password.dat";
    private static final int MAX_ATTEMPTS = 3;
    private static final int MAX_PASSWORD_LENGTH = 64;
    private static final int MAX_TOTP_LENGTH = 6;
    private static final Pattern NUMBER_PATTERN = Pattern.compile("\\d+");

    private final Scanner scanner;

    public AuthService(Scanner scanner) throws Exception {
        this.scanner = scanner;

        String masterPasswordHash = loadOrCreatePassword();
        String totpSecret = TOTPService.loadOrCreateSecret();

        exibirInformacoesTOTP(totpSecret);

        String sessionPassword = autenticarUsuario(masterPasswordHash, totpSecret);

        if (sessionPassword == null) {
            throw new Exception("Falha na autenticação após múltiplas tentativas.");
        }

        String salt = EncryptionService.getOrCreatePersistentSalt();
        EncryptionService.setSessionKeyAndSalt(sessionPassword, salt);
    }

    private void exibirInformacoesTOTP(String totpSecret) {
        System.out.println("\nAutenticação de Dois Fatores (TOTP) está ativada.");
        System.out.println("Use este segredo no seu aplicativo autenticador:");
        System.out.println(TOTPService.getBase32Secret(totpSecret));
        System.out.println("Ou escaneie o QR code com esta URL:");
        System.out.println(TOTPService.getOtpAuthUrl(totpSecret, "user@example.com", "SecurePasswordManager"));
    }

    private String autenticarUsuario(String passwordHash, String totpSecret) {
        int attempts = 0;
        while (attempts < MAX_ATTEMPTS) {
            attempts++;

            String inputPassword = solicitarEntrada("Digite a senha mestre: ", MAX_PASSWORD_LENGTH, false);
            if (!BCrypt.checkpw(inputPassword, passwordHash)) {
                System.out.println("Senha incorreta.");
                continue;
            }

            String totpCode = solicitarEntrada("Digite o código TOTP atual: ", MAX_TOTP_LENGTH, true);
            if (!NUMBER_PATTERN.matcher(totpCode).matches()) {
                System.out.println("Código inválido: apenas números são permitidos.");
                continue;
            }

            if (TOTPService.validateCode(totpSecret, totpCode)) {
                System.out.println("Autenticação bem-sucedida.");
                return inputPassword;
            } else {
                System.out.println("Código TOTP inválido.");
            }
        }

        return null;
    }

    private String solicitarEntrada(String mensagem, int maxLength, boolean apenasNumeros) {
        while (true) {
            try {
                System.out.print(mensagem);
                return InputSanitizer.sanitize(scanner.nextLine(), maxLength, apenasNumeros);
            } catch (IllegalArgumentException ex) {
                System.out.println("Entrada inválida. " + InputSanitizer.escapeForLog(ex.getMessage()));
            }
        }
    }

    String loadOrCreatePassword() throws Exception {
        Path path = Paths.get(PASSWORD_FILE);

        if (Files.exists(path)) {
            return Files.readString(path).trim();
        }

        System.out.println("Nenhuma senha mestre encontrada. Crie uma agora.");

        while (true) {
            String novaSenha = solicitarEntrada("Nova senha: ", MAX_PASSWORD_LENGTH, false);

            if (!senhaValida(novaSenha)) {
                continue;
            }

            String confirmacao = solicitarEntrada("Confirme a senha: ", MAX_PASSWORD_LENGTH, false);

            if (!novaSenha.equals(confirmacao)) {
                System.out.println("As senhas não coincidem. Tente novamente.");
                continue;
            }

            String hash = BCrypt.hashpw(novaSenha, BCrypt.gensalt());
            Files.writeString(path, hash);
            System.out.println("Senha mestre criada e salva.");
            return hash;
        }
    }

    private boolean senhaValida(String senha) {
        int breachCount = PasswordBreachChecker.checkPassword(senha);

        if (breachCount < 0) {
            System.out.println("Erro ao verificar vazamentos. Tente novamente.");
            return false;
        }

        if (breachCount > 0) {
            System.out.printf("A senha foi encontrada em %d vazamento(s). Escolha outra.%n", breachCount);
            return false;
        }

        if (senha.length() < 8) {
            System.out.println("A senha deve ter no mínimo 8 caracteres.");
            return false;
        }

        return true;
    }
}
