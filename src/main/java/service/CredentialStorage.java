package service;

import model.Credential;
import utils.InputSanitizer;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class CredentialStorage {
    private static final Path FILE_PATH = Paths.get("credentials.dat");
    private static final Path BACKUP_PATH = Paths.get("credentials_backup.dat");

    /**
     * Salva a lista de credenciais no arquivo criptografado.
     *
     * @param credentials Lista de credenciais a serem salvas.
     * @throws Exception Se ocorrer erro de I/O ou criptografia.
     */
    public static void saveCredentials(List<Credential> credentials) throws Exception {
        List<String> linhas = new ArrayList<>();

        for (Credential c : credentials) {
            try {
                String linha = montarLinhaSanitizada(c);
                String linhaCriptografada = EncryptionService.encrypt(linha);
                linhas.add(linhaCriptografada);
            } catch (IllegalArgumentException e) {
                System.err.println("Credencial ignorada por erro de sanitização: " + e.getMessage());
            }
        }

        criarBackupSeExistir();

        try (BufferedWriter writer = Files.newBufferedWriter(FILE_PATH)) {
            for (String linha : linhas) {
                writer.write(linha);
                writer.newLine();
            }
        } catch (IOException e) {
            throw new IOException("Falha ao escrever no arquivo: " + e.getMessage(), e);
        }
    }

    /**
     * Carrega as credenciais do arquivo criptografado.
     *
     * @return Lista de credenciais.
     * @throws Exception Se ocorrer erro de leitura ou descriptografia.
     */
    public static List<Credential> loadCredentials() throws Exception {
        List<Credential> credentials = new ArrayList<>();

        if (!Files.exists(FILE_PATH)) {
            return credentials;
        }

        try (BufferedReader reader = Files.newBufferedReader(FILE_PATH)) {
            String linha;
            while ((linha = reader.readLine()) != null) {
                try {
                    Credential cred = converterLinhaParaCredencial(linha);
                    if (cred != null) {
                        credentials.add(cred);
                    }
                } catch (Exception e) {
                    System.err.println("Erro ao processar linha: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            throw new IOException("Erro ao ler arquivo de credenciais: " + e.getMessage(), e);
        }

        return credentials;
    }

    // ========== Métodos Privados Auxiliares ==========

    private static void criarBackupSeExistir() throws IOException {
        if (Files.exists(FILE_PATH)) {
            Files.copy(FILE_PATH, BACKUP_PATH, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String montarLinhaSanitizada(Credential cred) {
        String servico = InputSanitizer.sanitize(cred.serviceName(), 50, false);
        String usuario = InputSanitizer.sanitize(cred.username(), 50, false);
        String senhaCriptografada = InputSanitizer.sanitize(cred.encryptedPassword(), 128, false);

        return String.join(",", servico, usuario, senhaCriptografada);
    }

    private static Credential converterLinhaParaCredencial(String linhaCriptografada) throws Exception {
        String linhaDescriptografada = EncryptionService.decrypt(linhaCriptografada);
        String[] partes = linhaDescriptografada.split(",", 3);

        if (partes.length != 3) {
            System.err.println("Formato inválido de linha: " + linhaDescriptografada);
            return null;
        }

        String servico = InputSanitizer.sanitize(partes[0], 50, false);
        String usuario = InputSanitizer.sanitize(partes[1], 50, false);
        String senha = InputSanitizer.sanitize(partes[2], 128, false);

        return new Credential(servico, usuario, senha);
    }
}
