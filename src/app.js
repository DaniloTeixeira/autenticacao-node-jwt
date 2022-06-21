require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Configure JSON response
app.use(express.json());

//Models
const User = require('./models/User');

// Public Route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Bem vindo a nossa API!' });
});

//Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // Check if user exists
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado.' });
    }

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!' });
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);

        next();
    } catch (error) {
        res.status(400).json({ msg: 'Token inválido.' });
    }
}

// Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    //Validations
    if (!name || !email || !password) {
        return res.status(400).json({ msg: 'Preencha todos os campos.' });
    }

    if (password !== confirmPassword) {
        return res.status(401).json({ msg: 'As senhas não conferem.' });
    }

    // Check if user exists
    const isUserExists = await User.findOne({ email });

    if (isUserExists) {
        return res.status(400).json({ msg: 'E-mail já cadastrado, utilize um e-mail diferente.' });
    }

    // Create password Hash
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário cadastrado com sucesso!' });

    } catch (error) {
        res.status(500).json({ msg: 'Erro interno no servidor, tente novamente!' });
    }
});

// Sign In
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ msg: 'Preencha todos os campos.' });
    }

    // Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não cadastrado.' });
    }

    // Check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(401).json({ msg: 'Usuário ou senha inválidos.' });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            { id: user._id },
            secret
        );
        res.status(200).json({ msg: 'Autenticação realizada com sucesso!', token });

    } catch (error) {
        res.status(500).json({ msg: 'Erro ao autenticar o usuário, tente novamente.' });
    }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;
const connectionURL = `mongodb+srv://${dbUser}:${dbPass}@cluster0.iyjxlwh.mongodb.net/AuthNodeJS?retryWrites=true&w=majority`;

mongoose
    .connect(connectionURL)
    .then(() => {
        app.listen(3000);
        console.log('Servidor conectado na porta 3000.');
    })
    .catch((error) => console.log(error));
