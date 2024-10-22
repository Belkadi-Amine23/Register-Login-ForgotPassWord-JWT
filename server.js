const express = require('express');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const csv = require('csv-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authenticateToken = require('./middlewares/authenticate');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'votre_secret_pour_signer_les_jwt';

app.use(express.json());
app.use(express.static('public')); // Pour servir les fichiers statiques (login.html)
app.use(cookieParser());

let utilisateurs = [];
fs.createReadStream('./data/utilisateurs.csv')
  .pipe(csv())
  .on('data', (row) => utilisateurs.push(row))
  .on('end', () => console.log('Utilisateurs chargés.'));

// Fonction pour générer un token JWT
function generateToken(user) {
  return jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
}

// Route pour afficher la page de login
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

// Route de login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = utilisateurs.find((u) => u.email === email);

  if (!user) return res.status(401).json({ message: 'Utilisateur non trouvé' });

  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      const token = generateToken(user);
      res.cookie('token', token, { httpOnly: true });
      return res.status(200).json({ message: 'Connexion réussie' });
    } else {
      return res.status(401).json({ message: 'Mot de passe incorrect' });
    }
  });
});

// Routes protégées
const userApiRoutes = require('./routes/userApi');
app.use('/user/api', authenticateToken, userApiRoutes);

app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
