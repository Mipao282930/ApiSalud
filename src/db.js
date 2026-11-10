const bcrypt = require('bcryptjs')
// Datos de prueba solo para la práctica
const usuarios = [
 { id: 1, nombre: 'Administrador', correo: 'admin@mail.com',
 clave: bcrypt.hashSync('Admin#2026', 10), rol: 'admin' },
 { id: 2, nombre: 'Ana Torres', correo: 'ana@mail.com',
 clave: bcrypt.hashSync('Ana#2026x', 10), rol: 'user' },
 { id: 3, nombre: 'Luis Ramos', correo: 'luis@mail.com',
 clave: bcrypt.hashSync('Luis#2026', 10), rol: 'user' },
]
const tareas = [
 { id: 1, titulo: 'Preparar informe de React', hecha: false, usuarioId: 2 },
 { id: 2, titulo: 'Estudiar MongoDB', hecha: true, usuarioId: 2 },
 { id: 3, titulo: 'Revisar seguridad de la API', hecha: false, usuarioId: 3 },
]
module.exports = { usuarios, tareas }
