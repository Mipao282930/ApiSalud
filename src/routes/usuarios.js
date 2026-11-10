const express = require('express')
const { usuarios } = require('../db')
const { autenticar, soloRol } = require('../middleware/auth')
const router = express.Router()
// Función de administrador: solo el rol admin
router.get('/', autenticar, soloRol('admin'), (req, res) => {
 res.json(usuarios.map(({ clave, ...resto }) => resto)) // sin la clave
})
// Perfil del propio usuario
router.get('/yo', autenticar, (req, res) => {
 const u = usuarios.find(x => x.id === req.usuario.id)
 if (!u) return res.status(404).json({ error: 'Usuario no encontrado' })
 const { clave, ...resto } = u
 res.json(resto)
})
module.exports = router