package service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * EncryptionService fornece criptografia e descriptografia segura de dados sensíveis usando AES-GCM.
 * A chave de criptografia é derivada da senha mestre do usuário e de um salt persistente usando PBKDF2.
 * A chave e o salt permanecem apenas na memória durante a sessão e são limpos ao encerrar a JVM.
 *
 * Uso:
 * - Após a autenticação, chame setSessionKeyAndSalt(masterPassword, salt) para inicializar a chave da sessão.
 *   Nota: `setSessionKeyAndSalt` deve ser chamado antes de encrypt() ou decrypt() para evitar erros.
 * - Use encrypt() e decrypt() para operações seguras com dados.
 * - O salt persistente é gerenciado no arquivo encryption_salt.dat.
 *
 * Notas de segurança:
 * - Chaves e salts são limpos da memória quando a JVM é encerrada, via hook de desligamento.
 * - AES/GCM/NoPadding é utilizado, garantindo criptografia autenticada.
 */
public class EncryptionService {

	private static String sessionKey = null;
	private static String sessionSalt = null;

	public static void setSessionKeyAndSalt(String chave, String salt) {
		sessionKey = chave;
		sessionSalt = salt;
	}

	private static SecretKey getSessionSecretKey() throws Exception {
		if (sessionKey == null || sessionSalt == null) {
			throw new IllegalStateException("A chave e o salt da sessão devem ser definidos antes da criptografia/descriptografia.");
		}
		return getSecretKey(sessionKey, sessionSalt);
	}

	public static void clearSessionKeyAndSalt() {
		sessionKey = null;
		sessionSalt = null;
	}

	// Chamada automática no encerramento da JVM para limpar dados sensíveis da memória
	static {
		Runtime.getRuntime().addShutdownHook(new Thread(EncryptionService::clearSessionKeyAndSalt));
	}

	/**
	 * Gera uma SecretKey a partir de uma senha e um salt, usando PBKDF2 com HMAC SHA-256.
	 *
	 * @param password A senha usada para derivar a chave
	 * @param salt     O salt como string
	 * @return Uma chave secreta adequada para criptografia AES
	 * @throws Exception Se a geração da chave falhar
	 */
	public static SecretKey getSecretKey(String password, String salt) throws Exception {
		byte[] saltBytes = salt.getBytes();
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}

	/**
	 * Criptografa uma string de texto usando AES/GCM/NoPadding.
	 * Um IV (vetor de inicialização) aleatório é gerado e adicionado aos dados criptografados.
	 * O resultado final é codificado em Base64.
	 *
	 * @param strToEncrypt Texto em formato string a ser criptografado
	 * @return String codificada em Base64 contendo IV + dados criptografados
	 * @throws Exception Se a criptografia falhar
	 */
	public static String encrypt(String strToEncrypt) throws Exception {
		if (strToEncrypt == null) {
			throw new NullPointerException("O texto a ser criptografado não pode ser nulo");
		}
		SecretKey key = getSessionSecretKey();
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] iv = new byte[12];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(iv);
		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
		byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes());
		byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
		System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
		System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);
		return Base64.getEncoder().encodeToString(encryptedWithIv);
	}

	/**
	 * Descriptografa uma string codificada em Base64 contendo um IV de 12 bytes seguido dos dados criptografados.
	 *
	 * @param strToDecrypt String codificada em Base64 com IV + dados criptografados
	 * @return A string de texto descriptografada
	 * @throws Exception Se a descriptografia falhar
	 */
	public static String decrypt(String strToDecrypt) throws Exception {
		try {
			SecretKey key = getSessionSecretKey();
			byte[] encryptedIvTextBytes = Base64.getDecoder().decode(strToDecrypt);
			if (encryptedIvTextBytes.length < 13) {
				throw new IllegalArgumentException("Comprimento da entrada criptografada é inválido");
			}
			byte[] iv = new byte[12];
			System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
			byte[] encryptedBytes = new byte[encryptedIvTextBytes.length - iv.length];
			System.arraycopy(encryptedIvTextBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
			cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
			byte[] decrypted = cipher.doFinal(encryptedBytes);
			return new String(decrypted);
		} catch (Exception e) {
			throw new Exception("Falha na descriptografia", e);
		}
	}

	/**
	 * Utilitário para gerar ou carregar um salt persistente para o PBKDF2.
	 *
	 * @return Uma string Base64 contendo o salt.
	 * @throws Exception Se houver falha na leitura ou escrita do arquivo de salt.
	 */
	public static String getOrCreatePersistentSalt() throws Exception {
		java.nio.file.Path saltPath = java.nio.file.Paths.get("encryption_salt.dat"); // Nome do arquivo de salt
		if (java.nio.file.Files.exists(saltPath)) {
			return java.nio.file.Files.readString(saltPath).trim();
		}
		// Gera um novo salt aleatório (16 bytes, codificado em Base64)
		byte[] saltBytes = new byte[16];
		new SecureRandom().nextBytes(saltBytes);
		String salt = Base64.getEncoder().encodeToString(saltBytes);
		java.nio.file.Files.writeString(saltPath, salt);
		return salt;
	}
}
