require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()
app.use(cors({ origin: '*' }))

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) => {
  res.status(200).json({ msg: 'bem vindo' })
})

app.get('/user/:id', checkToken, async (req, res) => {
  const id = req.params.id

  const user = await User.findById(id, '-password')

  if (!user) {
    return res.status(404).json({ msg: 'usuario nao encontrado' })
  }
  res.status(200).json({ user })
})

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ msg: 'acesso negado' })
  }

  try {
    const secret = process.env.SECRET
    jwt.verify(token, secret)
    next()
  } catch (err) {
    res.status(400).json({ msg: 'token invalido' })
  }
}

app.post('/auth/register', async (req, res) => {
  const { email, password, confirmPassword } = req.body

  if (!email) {
    return res.status(422).json({ msg: 'email obrigatorio' })
  }

  if (!password) {
    return res.status(422).json({ msg: 'senha obrigatoria' })
  }

  if (password !== confirmPassword) {
    return res.status(422).json({ msg: 'senhas nao conferem' })
  }

  const userExists = await User.findOne({ email: email })
  if (userExists) {
    return res.status(422).json({ msg: 'utilize outro email' })
  }

  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  const user = new User({
    email,
    password: passwordHash,
  })

  try {
    await user.save()

    res.status(201).json({ msg: 'usuario criado' })
  } catch (error) {
    res.status(500).json({ msg: ' erro' })
  }
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email) {
    return res.status(422).json({ msg: 'email obrigatorio' })
  }

  if (!password) {
    return res.status(422).json({ msg: 'senha obrigatoria' })
  }

  const user = await User.findOne({ email: email })
  const checkPassword = user && (await bcrypt.compare(password, user.password))
  if (!user || !checkPassword) {
    return res.status(404).json({ msg: 'Email e/ou senha invalida' })
  }

  try {
    const secret = process.env.SECRET

    const token = jwt.sign(
      {
        id: user.id,
      },
      secret
    )
    res.status(200).json({ msg: 'autenticado', token })
  } catch (err) {
    res.status(500).json({ msg: ' erro' })
  }
})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.b305mpg.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000)
    console.log('Servidor esta funcionando')
  })
  .catch((err) => console.log('err'))
