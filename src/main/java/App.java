import model.Credential;
import service.AuthService;
import service.CredentialStorage;
import service.CredentialManager;
import utils.InputSanitizer;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Scanner;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class App {

    /**
     * Ponto de entrada principal do Secure Password Manager.
     * Gerencia autenticação e interação com o usuário via CLI.
     *
     * @param args Argumentos da linha de comando (não utilizados).
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            new AuthService(scanner); // Autentica o usuário
        } catch (Exception e) {
            System.err.println("Falha na autenticação: " + e.getMessage());
            return;
        }

        List<Credential> credentials;
        try {
            credentials = CredentialStorage.loadCredentials(); // Carrega credenciais armazenadas
        } catch (Exception e) {
            System.err.println("Falha ao carregar credenciais: " + e.getMessage());
            return;
        }

        CredentialManager manager = new CredentialManager(credentials);
        manager.showMenu(); // Mostra o menu de gerenciamento de credenciais
    }

    /**
     * Verifica se o sufixo do hash SHA-1 da senha foi encontrado em vazamentos conhecidos,
     * utilizando a API Have I Been Pwned (HIBP).
     * A API usa k-anonimidade, enviando apenas o prefixo do hash para consulta.
     *
     * @param prefix Os primeiros 5 caracteres do hash SHA-1 da senha.
     * @param suffix O restante do hash SHA-1 da senha.
     * @return {@code true} se o sufixo foi encontrado em vazamentos; {@code false} caso contrário.
     * @throws Exception Em caso de falha na validação ou conexão.
     */
    static boolean checkPwned(String prefix, String suffix) throws Exception {
        // Sanitiza os inputs para garantir segurança
        try {
            prefix = InputSanitizer.sanitize(prefix, 5, false);
            suffix = InputSanitizer.sanitize(suffix, 100, false);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Falha na validação de entrada: " + e.getMessage());
        }

        HttpURLConnection conn = getHttpURLConnection(prefix, suffix);

        try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = in.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length > 0 && parts[0].equalsIgnoreCase(suffix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Configura uma conexão HTTP para consultar a API HIBP sobre senhas vazadas.
     *
     * @param prefix Os primeiros 5 caracteres do hash SHA-1 da senha.
     * @param suffix O restante do hash SHA-1 da senha (usado só para validação).
     * @return Uma conexão HTTP configurada para consulta da API.
     * @throws URISyntaxException Se a URI construída for inválida.
     * @throws IOException Se falhar a conexão.
     */
    private static HttpURLConnection getHttpURLConnection(String prefix, String suffix)
            throws URISyntaxException, IOException {

        // Validação rigorosa do prefixo e sufixo, aceitando só hexadecimais
        if (!prefix.matches("[A-Fa-f0-9]{5}")) {
            throw new IllegalArgumentException("Prefixo deve conter exatamente 5 caracteres hexadecimais.");
        }
        if (!suffix.matches("[A-Fa-f0-9]+")) {
            throw new IllegalArgumentException("Sufixo deve conter apenas caracteres hexadecimais.");
        }

        URI uri = new URI("https", "api.pwnedpasswords.com", "/range/" + prefix, null);
        URL url = uri.toURL();

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000); // Timeout de conexão
        conn.setReadTimeout(5000);    // Timeout de leitura
        return conn;
    }
}
