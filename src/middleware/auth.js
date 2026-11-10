const jwt = require('jsonwebtoken')
function autenticar(req, res, next) {
 const cabecera = req.headers.authorization || ''
 const [tipo, token] = cabecera.split(' ')
 if (tipo !== 'Bearer' || !token) {
 return res.status(401).json({ error: 'Token requerido' })
 }
 try {
 // Solo se acepta el algoritmo esperado
 req.usuario = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })
 next()
 } catch (e) {
 return res.status(401).json({ error: 'Token inválido o expirado' })
 }
}
function soloRol(...roles) {
 return (req, res, next) => {
 if (!roles.includes(req.usuario.rol)) {
 return res.status(403).json({ error: 'No tiene permisos para esta acción' })
 }
 next()
 }
}
module.exports = { autenticar, soloRol }
