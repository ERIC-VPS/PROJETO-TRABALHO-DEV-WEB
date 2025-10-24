// 1. Importa as ferramentas
const express = require('express');
const path = require('path');
const postgres = require('postgres'); // <-- NOVO: Importa o postgres.js
const bcrypt = require('bcryptjs'); // <-- NOVO: Importa o bcrypt

const app = express();
const port = 3000;


// --- Conexão com o Banco de Dados ---
// (Usando o usuário 'teste' e senha '1234' que você criou)
let sql;
try {
    sql = postgres('postgres://teste:1234@localhost:5432/cliniweb_db');
    console.log("Conexão com o PostgreSQL bem-sucedida!");
} catch (error) {
    console.error("Falha ao conectar ao PostgreSQL:", error.message);
    process.exit(1); // Encerra o app se não conseguir conectar
}
// --- Middlewares ---
// (NOVO!) Ensina o Express a ler JSON vindo do frontend
app.use(express.json()); 

// Ensina o Express a servir os arquivos da pasta 'public'
app.use(express.static(path.join(__dirname, 'public')));



// (NOVO!) ROTA DE CADASTRO
app.post('/api/cadastro', async (req, res) => {
    try {
        // 1. Pega os dados do corpo da requisição
        const { email, senha, tipoUsuario } = req.body;

        // 2. Validação simples
        if (!email || !senha || !tipoUsuario) {
            return res.status(400).json({ message: "Email, senha e tipo de usuário são obrigatórios." });
        }

        // 3. Criptografar a senha (NUNCA salve senha em texto puro)
        const salt = await bcrypt.genSalt(10); // Gera o "tempero"
        const senhaHash = await bcrypt.hash(senha, salt); // Criptografa

        console.log(`Tentando cadastrar usuário: ${email} com hash: ${senhaHash}`);

        // 4. Inserir no Banco de Dados
        // Usamos `` (crase) para queries SQL
        await sql`
            INSERT INTO usuarios (email, senha, tipo_usuario)
            VALUES (${email}, ${senhaHash}, ${tipoUsuario})
        `;

        // 5. Sucesso!
        // Status 201 significa "Created" (Criado)
        res.status(201).json({ message: "Usuário cadastrado com sucesso!" });

    } catch (error) {
        // 6. Tratar erros
        console.error("Erro no cadastro:", error.message);

        if (error.code === '23505') { // Código de erro do Postgres para 'UNIQUE VIOLATION'
            return res.status(409).json({ message: "Este email já está cadastrado." });
        }
        
        res.status(500).json({ message: "Erro interno do servidor." });
    }
});


// (A NOVA ROTA DE LOGIN, COM BANCO DE DADOS)
// (A ROTA DE LOGIN ATUALIZADA E MAIS SEGURA)
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha, tipoUsuario } = req.body;

        // (NOVO) Define a mensagem de erro genérica
        const MENSAGEM_FALHA = "Email, senha ou tipo de usuário incorretos."; // <-- MUDANÇA

        if (!email || !senha || !tipoUsuario) {
            return res.status(400).json({ success: false, message: MENSAGEM_FALHA }); // <-- MUDANÇA
        }

        console.log(`Tentativa de login recebida para: ${email} como ${tipoUsuario}`);

        // 2. Busca o usuário no banco de dados pelo email
        const usuariosEncontrados = await sql`
            SELECT * FROM usuarios WHERE email = ${email}
        `;

        // 3. Verifica se o usuário existe
        if (usuariosEncontrados.length === 0) {
            console.log("Login falhou: Email não encontrado.");
            // Retorna a mensagem genérica
            return res.status(401).json({ success: false, message: MENSAGEM_FALHA }); // <-- MUDANÇA
        }

        const usuario = usuariosEncontrados[0];

        // 4. Verifica se o tipo de usuário está correto
        if (usuario.tipo_usuario !== tipoUsuario) {
            console.log("Login falhou: Tipo de usuário incorreto.");
            // Retorna a mensagem genérica
            return res.status(401).json({ success: false, message: MENSAGEM_FALHA }); // <-- MUDANÇA
        }

        // 5. Compara a senha enviada com o hash salvo no banco
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

        if (!senhaCorreta) {
            console.log("Login falhou: Senha incorreta.");
            // Retorna a mensagem genérica
            return res.status(401).json({ success: false, message: MENSAGEM_FALHA }); // <-- MUDANÇA
        }

        // 6. SUCESSO! O usuário está autenticado.
        console.log(`Login bem-sucedido para: ${email}`);

        // 7. Decide para onde redirecionar (lógica igual a antes)
        let redirectTo = 'login.html';
        if (usuario.tipo_usuario === 'paciente') {
            redirectTo = 'paciente-home.html';
        } else if (usuario.tipo_usuario === 'medico') {
            redirectTo = 'agenda-medico.html';
        } else if (usuario.tipo_usuario === 'admin') {
            redirectTo = 'admin-dashboard.html'; 
        }

        res.json({
            success: true,
            message: "Login bem-sucedido!",
            redirectTo: redirectTo
        });

    } catch (error) {
        console.error("Erro no login:", error.message);
        res.status(500).json({ success: false, message: "Erro interno do servidor." });
    }
});


// --- Iniciar o Servidor ---
app.listen(port, () => {
    console.log(`Servidor CliniWeb rodando!`);
    console.log(`Acesse seu site em: http://localhost:${port}`);
});