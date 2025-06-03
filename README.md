<div align="left">

## 🔐 gerenciador de senhas seguras

---
  
Um gerenciador de senhas seguro com autenticação em dois fatores (TOTP), criptografia avançada, verificação de vazamento de credenciais e geração de senhas fortes. Desenvolvido em Java.

---

## 🧩 Funcionalidades

- 🔑 Armazenamento de senhas criptografadas localmente
- 🔐 Autenticação com senha mestre (Master Password)
- 🕒 Suporte a autenticação TOTP (Two-Factor Authentication)
- 📦 Criptografia AES para armazenar dados
- 🌐 Verificação de senhas vazadas via API HaveIBeenPwned
- 🛡️ Validação de entrada e sanitização contra injeções
- 🧪 Testes unitários e estrutura modular

---

## 📁 Estrutura do Projeto

```text
Gerenciador_de_senhas/
├── src/
│   ├── main/java/
│   │   ├── model/
│   │   │   └── Credential.java
│   │   ├── service/
│   │   │   ├── AuthService.java
│   │   │   ├── CredentialManager.java
│   │   │   ├── CredentialStorage.java
│   │   │   ├── EncryptionService.java
│   │   │   ├── PasswordBreachChecker.java
│   │   │   └── TOTPService.java
│   │   ├── utils/
│   │   │   ├── InputSanitizer.java
│   │   │   └── PasswordGenerator.java
│   │   └── App.java
│   └── test/
├── totp_secret.dat
├── master_password.dat
├── pom.xml
└── README.md
```
## ⚙️ Requisitos

- Java 8+
- Maven 3.6+
- Aplicativo autenticador (Google Authenticator, Authy, etc.)

---

## 🚀 Como Executar

1. **Clone o projeto:**

```
git clone https://github.com/joseleonelmacedo/Gerenciador_de_senhas
cd Gerenciador_de_senhas
```
2. **Compile e execute:**
```
mvn clean install
mvn exec:java -Dexec.mainClass="App"
```

3. **Na primeira execução:**

Será solicitada a criação de uma senha mestre

Será gerado um código ou QR code para configurar o TOTP

Use um app autenticador para registrar esse código

---

## 🧪 Testes

Execute os testes com:
```
mvn test
```

## 🔒 Segurança

Senhas são criptografadas com AES antes de serem salvas
Autenticação requer senha mestre + código TOTP
As credenciais são armazenadas localmente em formato criptografado
As senhas podem ser verificadas contra vazamentos online

## 📸 Exemplo de uso
```
Digite a senha mestre: **********
Digite o código TOTP atual: ******

✅ Login bem-sucedido!

1. Adicionar nova credencial
2. Listar credenciais
3. Verificar senha em vazamentos
4. Gerar senha segura
...
```
