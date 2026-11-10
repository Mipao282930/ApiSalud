require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error('Falta JWT_SECRET en el archivo .env');
    process.exit(1);
}

// 1. Cabeceras de seguridad, CORS, límite de tamaño y de peticiones
app.use(helmet());
app.use(cors({ origin: ['http://localhost:5173'], methods: ['GET', 'POST', 'DELETE'] }));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimit({ windowMs: 60 * 1000, max: 100 }));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Demasiados intentos, espere 15 minutos' }
});

// 2. Datos de ejemplo (en un sistema real vendrían de una base de datos)
const users = [
    { id: 1, username: 'admin', passwordHash: bcrypt.hashSync('Admin123!', 10), rol: 'admin' },
    { id: 2, username: 'vendedor', passwordHash: bcrypt.hashSync('Venta123!', 10), rol: 'usuario' }
];

let productos = [
    { id: 1, nombre: 'Laptop', precio: 2500 },
    { id: 2, nombre: 'Mouse', precio: 45 }
];

// 3. Middlewares de validación, autenticación y autorización
const validar = (req, res, next) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
        return res.status(400).json({ errores: errores.array().map(e => e.msg) });
    }
    next();
};

const autenticar = (req, res, next) => {
    const [tipo, token] = (req.headers.authorization || '').split(' ');
    if (tipo !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Token requerido' });
    }
    try {
        req.usuario = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Token inválido o vencido' });
    }
};

const soloRol = (...roles) => (req, res, next) =>
    roles.includes(req.usuario.rol) ? next() : res.status(403).json({ error: 'Acceso denegado' });

// 4. Rutas
app.post('/api/login',
    loginLimiter,
    body('username').isString().trim().notEmpty().withMessage('username es obligatorio'),
    body('password').isString().notEmpty().withMessage('password es obligatorio'),
    validar,
    (req, res) => {
        const u = users.find(x => x.username === req.body.username);
        if (!u || !bcrypt.compareSync(req.body.password, u.passwordHash)) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }
        const token = jwt.sign({ id: u.id, rol: u.rol }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '15m' });
        res.json({ token });
    }
);

app.get('/api/productos', autenticar, (req, res) => res.json(productos));

app.post('/api/productos',
    autenticar,
    soloRol('admin'),
    body('nombre').isString().trim().isLength({ min: 2, max: 50 }).withMessage('nombre debe tener de 2 a 50 caracteres'),
    body('precio').isFloat({ gt: 0 }).withMessage('precio debe ser un número mayor que 0'),
    validar,
    (req, res) => {
        const nuevo = { 
            id: productos.length ? Math.max(...productos.map(p => p.id)) + 1 : 1, 
            nombre: req.body.nombre, 
            precio: Number(req.body.precio) 
        };
        productos.push(nuevo);
        res.status(201).json(nuevo);
    }
);

app.delete('/api/productos/:id',
    autenticar,
    soloRol('admin'),
    param('id').isInt({ min: 1 }).withMessage('id inválido'),
    validar,
    (req, res) => {
        const antes = productos.length;
        productos = productos.filter(p => p.id !== Number(req.params.id));
        if (productos.length === antes) return res.status(404).json({ error: 'Producto no encontrado' });
        res.status(204).end();
    }
);

// 5. Rutas inexistentes y errores sin revelar detalles internos
app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => console.log('API segura escuchando en el puerto ' + PORT));