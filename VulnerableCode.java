import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.util.Random;

/**
 * ATENÇÃO: 
 * ==========================================================
 * ESTE CÓDIGO É INTENCIONALMENTE VULNERÁVEL.
 *
 * Ele foi criado APENAS para fins educacionais, para que
 * ferramentas de SAST (CodeQL, Codacy, etc.) e de DAST 
 * possam identificar problemas de segurança.
 *
 * NÃO UTILIZAR NENHUMA DESTAS PRÁTICAS EM CÓDIGO REAL.
 * ==========================================================
 */
public class VulnerableCode {

    // 1) CREDENCIAIS EM CÓDIGO (HARD-CODED CREDENTIALS)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/minha_aplicacao";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "senha_super_secreta";

    // 2) SEGREDOS / CHAVES HARDCODED
    // Estilo de chave que ferramentas de secret-scanning costumam detectar.
    private static final String API_KEY = "AKIA1234567890FAKEEXAMPLEKEY";
    private static final String PRIVATE_KEY =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n" +
            "-----END PRIVATE KEY-----";

    /**
     * Simula um processo de login extremamente inseguro.
     *
     * Vulnerabilidades principais:
     * - SQL Injection
     * - Credenciais em código
     * - Uso de Statement em vez de PreparedStatement.
     */
    public boolean loginInseguro(String username, String password) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // 3) SQL INJECTION
            String sql = "SELECT * FROM usuarios WHERE username = '" + username
                       + "' AND password = '" + password + "'";

            stmt = conn.createStatement();
            rs = stmt.executeQuery(sql);

            return rs.next(); // se encontrou algum registro, considera login válido

        } catch (Exception e) {
            // 4) TRATAMENTO GENÉRICO + STACKTRACE
            e.printStackTrace();
            return false;

        } finally {
            try {
                if (rs != null) rs.close();
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (Exception ignored) {
                // Ignorando exceção de fechamento (má prática)
            }
        }
    }

    /**
     * Simula uma busca de usuários por termo de pesquisa.
     *
     * Vulnerabilidade: SQL Injection pela concatenação da string "searchTerm".
     */
    public void buscarUsuarioPorTermo(String searchTerm) {
        Connection conn = null;
        Statement stmt = null;

        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // 5) SQL INJECTION EM CONSULTA DE BUSCA
            String sql = "SELECT * FROM usuarios WHERE nome LIKE '%" + searchTerm + "%'";
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                System.out.println("Usuário encontrado: " + rs.getString("nome"));
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Exemplo de armazenamento de senha com algoritmo fraco.
     *
     * Vulnerabilidade:
     * - Uso de MD5 sem salt, considerado inseguro.
     */
    public String armazenarSenhaInsegura(String senhaPlano) {
        try {
            // 6) USO DE ALGORITMO CRIPTOGRÁFICO FRACO (MD5)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(senhaPlano.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }

            String hashInseguro = sb.toString();
            System.out.println("Senha armazenada (hash inseguro MD5): " + hashInseguro);
            return hashInseguro;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Armazena a senha em texto puro em um arquivo.
     *
     * Vulnerabilidades:
     * - Armazenamento de credenciais em texto puro.
     * - Possível path traversal se o caminho for manipulável.
     */
    public void salvarSenhaEmArquivo(String caminhoArquivo, String senhaPlano) {
        FileWriter fw = null;
        try {
            // Caminho recebido de fora, sem validação (path traversal)
            fw = new FileWriter(caminhoArquivo, true);
            fw.write("senha=" + senhaPlano + "\n");
            fw.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fw != null) fw.close();
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Simula geração de HTML sem sanitização de entrada.
     *
     * Vulnerabilidade:
     * - XSS (Cross-Site Scripting).
     */
    public String gerarPaginaPerfil(String nome) {
        // 7) XSS – entrada do usuário é colocada diretamente no HTML
        String html =
                "<html>" +
                "<head><title>Perfil do Usuário</title></head>" +
                "<body>" +
                "<h1>Bem-vindo, " + nome + "!</h1>" +
                "<p>Esse é o seu painel.</p>" +
                "</body>" +
                "</html>";

        return html;
    }

    /**
     * Gera um token de sessão de forma totalmente previsível.
     *
     * Vulnerabilidades:
     * - Uso de Random com seed fixa.
     * - Token de sessão baseado em dados previsíveis.
     */
    public String gerarTokenSessaoInseguro(String username) {
        // Seed fixa => sequências sempre iguais
        Random random = new Random(1234);
        int valorAleatorio = random.nextInt(999999);

        String token = username + "-" + System.currentTimeMillis() + "-" + valorAleatorio;
        System.out.println("Token de sessão gerado (inseguro): " + token);
        return token;
    }

    /**
     * Executa um comando do sistema concatenando diretamente a entrada.
     *
     * Vulnerabilidade:
     * - Command Injection.
     */
    public void executarComandoSistema(String comando) {
        try {
            // Exemplo: "ls", "rm -rf /", etc. (NÃO EXECUTAR EM PRODUÇÃO)
            String cmd = "sh -c " + comando;
            Process p = Runtime.getRuntime().exec(cmd);
            // Ignorando saída / erros do processo (má prática adicional)
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Lê um arquivo com caminho fornecido externamente.
     *
     * Vulnerabilidade:
     * - Possível Path Traversal: o usuário pode usar "../" etc.
     */
    public void lerArquivoUsuario(String caminhoRelativo) {
        FileInputStream fis = null;
        try {
            // Sem qualquer validação do caminho
            String caminhoCompleto = "/var/app/arquivos/" + caminhoRelativo;
            fis = new FileInputStream(caminhoCompleto);
            byte[] buffer = new byte[1024];
            int lidos = fis.read(buffer);
            System.out.println("Leu " + lidos + " bytes do arquivo do usuário.");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Desserializa dados arbitrários recebidos em um array de bytes.
     *
     * Vulnerabilidade:
     * - Insecure Deserialization.
     */
    public Object desserializarObjetoInseguro(byte[] dados) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(dados);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            System.out.println("Objeto desserializado (inseguro): " + obj);
            return obj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Método main para facilitar testes básicos.
     */
    public static void main(String[] args) {
        VulnerableCode app = new VulnerableCode();

        // Exemplo de login inseguro
        System.out.println("Tentando login inseguro...");
        boolean autenticado = app.loginInseguro("admin", "admin123");
        System.out.println("Login realizado? " + autenticado);

        // Exemplo de busca insegura
        System.out.println("\nBuscando usuários com termo inseguro...");
        app.buscarUsuarioPorTermo("teste' OR '1'='1");

        // Exemplo de armazenamento de senha inseguro (hash fraco)
        System.out.println("\nArmazenando senha com MD5 (inseguro)...");
        String hash = app.armazenarSenhaInsegura("minha_senha_fraca");

        // Exemplo de gravação de senha em arquivo em texto puro
        System.out.println("\nSalvando senha em arquivo (texto puro, inseguro)...");
        app.salvarSenhaEmArquivo("senhas.txt", "minha_senha_fraca");

        // Exemplo de XSS
        System.out.println("\nGerando HTML de perfil (possível XSS)...");
        String pagina = app.gerarPaginaPerfil("<script>alert('XSS');</script>");
        System.out.println(pagina);

        // Exemplo de token de sessão inseguro
        System.out.println("\nGerando token de sessão inseguro...");
        app.gerarTokenSessaoInseguro("usuarioTeste");

        // Exemplo de command injection
        System.out.println("\nExecutando comando de sistema (inseguro)...");
        app.executarComandoSistema("ls"); // em Windows poderia ser "dir"

        // Exemplo de leitura de arquivo com possível path traversal
        System.out.println("\nLendo arquivo com caminho potencialmente inseguro...");
        app.lerArquivoUsuario("../segredos.txt");

        // Exemplo de desserialização insegura (apenas para disparar a lógica)
        System.out.println("\nDesserializando objeto de forma insegura...");
        byte[] dadosFalsos = new byte[] { 0x00, 0x01, 0x02 }; // isso deve gerar exceção
        app.desserializarObjetoInseguro(dadosFalsos);
    }
}
