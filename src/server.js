import express, { json } from "express";
import cors from "cors"
import { MongoClient } from "mongodb";
import dotenv from "dotenv"
import bcrypt from 'bcrypt';
import joi from "joi"
import { v4 as uuid } from 'uuid';
import dayjs from "dayjs";
import { ObjectID } from "bson";
dotenv.config()


// conexão com banco de dados
const server = express()
server.use(json())
server.use(cors())

const mongoClient = new MongoClient(process.env.DATABASE_URL)
let db;

mongoClient.connect().then(() => {
    db = mongoClient.db()
})
.catch(() => {
    console.log("Algo deu errado no banco de dados")
})


// rotas
server.post("/cadastro", async (req, res) => {
    const { nome, email, senha, confirmaSenha } = req.body

    const usuarioSchema = joi.object({
        nome: joi.string().required(),
        email: joi.string().email().required(),
        senha: joi.string().required(),
        confirmaSenha: joi.string().valid(joi.ref('senha')).required()
    })

    const { error } = usuarioSchema.validate({ nome, email, senha, confirmaSenha }, { abortEarly: false })

    if (error){
        const errosMensagens = error.details.map(err => err.message)
        return res.status(422).send(errosMensagens)
    }

    const senhaCriptografada = bcrypt.hashSync(senha, 10)

    try {
        const usuarioRepetido = await db.collection("usuarios").findOne({ email })
        if (usuarioRepetido) return res.status(401).send("Usuário já cadastrado!")
        await db.collection("usuarios").insertOne({ nome, email, senha: senhaCriptografada })
        res.status(201).send("Usuário cadastrado com sucesso!")
    } catch (err) {
        res.status(500).send(err.message);
    }
})

server.post("/login", async (req, res) => {
    const { email, senha } = req.body

    const usuarioSchema = joi.object({
        email: joi.string().email().required(),
        senha: joi.string().required()
    })

    const { error } = usuarioSchema.validate({ email, senha }, { abortEarly: false })

    if (error){
        const errosMensagens = error.details.map(err => err.message)
        return res.status(422).send(errosMensagens)
    }

    try {
        const checarUsuario = await db.collection("usuarios").findOne({ email })
        if (!checarUsuario) return res.status(400).send("Email ou senha incorretos")

        const checarSenha = bcrypt.compareSync(senha, checarUsuario.senha)
        if (!checarSenha) return res.status(400).send("Email ou senha incorretos")

        const token = uuid()

        const sessao = await db.collection("sessoes").insertOne({ idUsuario: checarUsuario._id, token })

        return res.send(token)
    } catch (err) {
        res.status(500).send(err.message)
    }
})

server.get("/registros", async (req, res) => {
    const token = req.headers.authorization?.replace("Bearer ", "")

    try {
        const usuarioSessao = await db.collection("sessoes").findOne({ token })
        if (!usuarioSessao) return res.status(401).send("Token invalido!")

        const usuario = await db.collection("usuarios").findOne({ _id: usuarioSessao.idUsuario })
        if (!usuario) return res.status(404).send("Usuario não encontrado!")

        const registros = await db.collection("registros").find({ idUsuario: usuario._id }).toArray()

        res.send(registros)

    } catch (error) {  
        res.status(500).send("Algo deu errado no banco de dados!")
    }
})  

server.post("/registros", async (req, res) => {
    const { valor, descricao } = req.body
    const token = req.headers.authorization?.replace("Bearer ", "")

    try {
        const usuarioSessao = await db.collection("sessoes").findOne({ token })
        if (!usuarioSessao) return res.status(401).send("Não existe usuario no DB sessoes!")

        const usuario = await db.collection("usuarios").findOne({ _id: usuarioSessao.idUsuario })
        if (!usuario) return res.status(404).send("Usuario não encontrado!")

        const registro = await db.collection("registros").insertOne({ 
            valor, 
            descricao, 
            data: dayjs().format("DD/MM"),
            idUsuario: usuarioSessao.idUsuario,
            nome: usuario.nome
        })
        const registros = await db.collection("registros").find({ idUsuario: registro.idUsuario }).toArray()
        if (!registros) return res.send("não existe registros nesse usuario!")

        res.send(registros)
    } catch (error) {
        res.status(500).send("deu algo errado!")
    }
})

server.get("/usuario", async (req, res) => {
    const token = req.headers.authorization?.replace("Bearer ", "")

    try {
        const usuarioSessao = await db.collection("sessoes").findOne({ token })
        if (!usuarioSessao) return res.status(401).send("Token invalido!")

        const usuario = await db.collection("usuarios").findOne({ _id: usuarioSessao.idUsuario })
        if (!usuario) return res.status(404).send("Usuario não encontrado!")

        res.send(usuario)
        
    } catch (error) {
        res.status(500).send("Algo deu errado na requisição dos dados do usuario!")
    }
})

const PORT = 5000
server.listen(PORT, () => console.log(`Estou rodando na porta ${PORT}`))