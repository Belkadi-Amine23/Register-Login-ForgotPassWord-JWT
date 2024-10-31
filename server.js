const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Secrets pour JWT
const JWT_SECRET = 'votre_secret'; // Changez cela pour quelque chose de sécurisé
const REFRESH_TOKEN_SECRET = 'votre_refresh_secret'; // Changez cela pour quelque chose de sécurisé

let refreshTokens = []; // Stockage des tokens de rafraîchissement

app.use(cors({
  origin: 'http://localhost:3000', // Changez cela si nécessaire
  credentials: true // Permet d'envoyer des cookies
}));

app.use(bodyParser.json());
app.use(cookieParser());

// Utilisateur fictif
const users = [{ email: 'user@example.com', password: 'password' }];

// Générer un token d'accès
function generateAccessToken(user) {
  return jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1m' });
}

// Générer un token de rafraîchissement
function generateRefreshToken(user) {
  return jwt.sign({ email: user.email }, REFRESH_TOKEN_SECRET);
}

// Authentifier l'utilisateur et générer les tokens
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);

  if (!user) return res.status(403).json({ message: 'Accès refusé' }); // Accès refusé

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  refreshTokens.push(refreshToken); // Ajouter le token de rafraîchissement à la liste

  res.cookie('token', accessToken, { httpOnly: true, secure: false }); // mettez secure: true en production
  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: false }); // mettez secure: true en production
  res.json({ accessToken });
});

// Rafraîchir le token
app.post('/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refreshToken; // Obtenir le token de rafraîchissement

  if (!refreshToken || !refreshTokens.includes(refreshToken)) {
    return res.sendStatus(403); // Accès refusé
  }

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Accès refusé

    const accessToken = generateAccessToken({ email: user.email });
    res.cookie('token', accessToken, { httpOnly: true, secure: false }); // mettez secure: true en production
    res.json({ accessToken });
  });
});

// Middleware d'authentification
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) return res.sendStatus(401); // Accès refusé

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token expiré' });
    req.user = user;
    next();
  });
}

// Endpoint protégé
app.get('/user/api', authenticateToken, (req, res) => {
  res.json({ message: 'Vous avez accès à l\'API utilisateur.' });
});

// Démarrer le serveur
app.listen(PORT, () => {
  console.log(`Le serveur écoute sur http://localhost:${PORT}`);
});
