require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const cors = require('cors')
const rateLimit = require('express-rate-limit')
// La API no inicia si el secreto falta o es débil
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
 console.error('Falta JWT_SECRET o es demasiado corto (mínimo 32 caracteres)')
 process.exit(1)
}
const app = express()
app.use(helmet()) // cabeceras seguras
app.use(cors({
 origin: process.env.CORS_ORIGIN || 'http://localhost:5173', // solo este origen
 methods: ['GET', 'POST', 'PUT', 'DELETE'],
 allowedHeaders: ['Content-Type', 'Authorization'],
}))
app.use(rateLimit({ // límite general
 windowMs: 15 * 60 * 1000,
 limit: 100,
 standardHeaders: true,
 legacyHeaders: false,
}))
app.use(express.json({ limit: '10kb' })) // cuerpo máximo de 10 kb
app.get('/api/salud', (req, res) => res.json({ estado: 'ok' }))
app.use('/api/auth', require('./routes/auth'))
app.use('/api/tareas', require('./routes/tareas'))
app.use('/api/usuarios', require('./routes/usuarios'))
// Ruta inexistente
app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada' }))
// Manejo de errores: mensajes genéricos, sin detalles internos
app.use((err, req, res, next) => {
 if (err.type === 'entity.too.large')
 return res.status(413).json({ error: 'Cuerpo de la petición demasiado grande' })
 if (err.type === 'entity.parse.failed')
 return res.status(400).json({ error: 'JSON inválido' })
 console.error(err) // el detalle queda solo en el servidor
 res.status(500).json({ error: 'Error interno del servidor' })
})
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`API segura en http://localhost:${PORT}`))