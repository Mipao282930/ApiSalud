const express = require('express')
const { tareas } = require('../db')
const { autenticar } = require('../middleware/auth')
const { textoValido } = require('../validar')
const router = express.Router()
router.use(autenticar) // todas las rutas de tareas exigen token
const esAdmin = (req) => req.usuario.rol === 'admin'
// Busca la tarea y comprueba que pertenezca al usuario (protección contra BOLA/IDOR)
function buscarTarea(req, res) {
 const id = Number(req.params.id)
 const tarea = Number.isInteger(id) ? tareas.find(t => t.id === id) : null
 if (!tarea || (!esAdmin(req) && tarea.usuarioId !== req.usuario.id)) {
 res.status(404).json({ error: 'Tarea no encontrada' })
 return null
 }
 return tarea
}
router.get('/', (req, res) => {
 const lista = esAdmin(req) ? tareas : tareas.filter(t => t.usuarioId === req.usuario.id)
 res.json(lista)
})
router.get('/:id', (req, res) => {
 const tarea = buscarTarea(req, res)
 if (tarea) res.json(tarea)
})
router.post('/', (req, res) => {
 const { titulo } = req.body || {}
 if (!textoValido(titulo, 3, 100))
 return res.status(400).json({ error: 'Título inválido (3 a 100 caracteres)' })
 const nueva = {
 id: Math.max(0, ...tareas.map(t => t.id)) + 1,
 titulo: titulo.trim(),
 hecha: false,
 usuarioId: req.usuario.id, // el dueño sale del token, no del cuerpo
 }
 tareas.push(nueva)
 res.status(201).json(nueva)
})
router.put('/:id', (req, res) => {
 const tarea = buscarTarea(req, res)
 if (!tarea) return
 const { titulo, hecha } = req.body || {}
 if (titulo !== undefined) {
 if (!textoValido(titulo, 3, 100))
 return res.status(400).json({ error: 'Título inválido' })
 tarea.titulo = titulo.trim()
 }
 if (hecha !== undefined) {
 if (typeof hecha !== 'boolean')
 return res.status(400).json({ error: 'El campo hecha debe ser true o false' })
 tarea.hecha = hecha
 }
 // Solo se modifican campos permitidos: id y usuarioId no se pueden cambiar
 res.json(tarea)
})
router.delete('/:id', (req, res) => {
 const tarea = buscarTarea(req, res)
 if (!tarea) return
 tareas.splice(tareas.indexOf(tarea), 1)
 res.status(204).end()
})
module.exports = router