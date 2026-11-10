const correoValido = (c) =>
 typeof c === 'string' && c.length <= 100 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c)
// 8 a 72 caracteres (límite de bcrypt), con mayúscula, minúscula y número
const claveFuerte = (c) =>
 typeof c === 'string' && c.length >= 8 && c.length <= 72 &&
 /[A-Z]/.test(c) && /[a-z]/.test(c) && /[0-9]/.test(c)
const textoValido = (t, min, max) =>
 typeof t === 'string' && t.trim().length >= min && t.length <= max
module.exports = { correoValido, claveFuerte, textoValido }