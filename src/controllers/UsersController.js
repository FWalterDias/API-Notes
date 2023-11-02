// pode ter ate 5 metodos
// index - GET para listar vários registros.
// show - GET para exibir um registro específico.
// create - POST para criar um registro.
// update - PUT para atualizar um registro.
// delete - DELETE para remover um resgistro.

const AppError = require("../utils/AppError");
const sqliteConnection = require("../database/sqlite");
const { hash, compare } = require("bcryptjs");

class UsersController {

    async create(req, res) {
        const { name, email, password } = req.body;

        const database = await sqliteConnection();

        const existEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

        if (existEmail) {
            throw new AppError("Este email já está em uso");
        }

        const hashedPassword = await hash(password, 8);

        await database.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);

        return res.status(201).json();
    }

    async update(req, res) {
        const { id } = req.params;
        const { name, email, password, old_password } = req.body;

        const database = await sqliteConnection();

        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);

        if(!user){
            throw new AppError("Usuário não encontrado!")
        }

        const userWhithUpdateEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

        if(userWhithUpdateEmail && userWhithUpdateEmail.id !== user.id){
            throw new AppError("Email já cadastrado para outro usuário")
        }

        user.name = name ?? user.name;
        user.email = email ?? user.email;

        if(password && !old_password){
            throw new AppError("Você precisa informar a senha antiga");
        }

        if(password && old_password){
            const checkOldPassword = await compare(old_password, user.password)

            if(!checkOldPassword){
                throw new AppError("As senhas não conferem");
            }

            user.password = await hash(password, 8);
        }



        await database.run(`
            UPDATE users SET
            name = ?,
            email = ?,
            password = ?,
            updated_at = DATETIME("NOW")
            
            WHERE id = ?
        `, [user.name, user.email, user.password, id]);

        return res.json();
    }
}

module.exports = UsersController;