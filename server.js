const express = require('express');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const csv = require('csv-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authenticateToken = require('./middlewares/authenticate');
// Import nodemailer
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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

// la route Register 
const path = require('path'); // pour servir les fichiers statiques

// Charger bcrypt, fs, et express si ce n’est pas déjà fait

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Vérifier si l'email existe déjà
  const userExists = utilisateurs.some((u) => u.email === email);
  if (userExists) {
    return res.status(400).json({ message: 'Cet email est déjà enregistré.' });
  }

  // Hasher le mot de passe
  const hashedPassword = await bcrypt.hash(password, 10);

  // Sauvegarder dans le fichier CSV
  const newUser = `${email},${hashedPassword}\n`;
  fs.appendFile('./data/utilisateurs.csv', newUser, (err) => {
    if (err) return res.status(500).json({ message: 'Erreur lors de l\'enregistrement de l\'utilisateur.' });
    utilisateurs.push({ email, password: hashedPassword }); // Mettre à jour le tableau en mémoire
    res.status(201).json({ message: 'Inscription réussie !' });
  });
});


//Configuration de Nodemailer et route forgot-password


// Configurer le transporteur d'email
const transporter = nodemailer.createTransport({
  service: 'Gmail', // ou votre service email
  auth: {
    user: 'm.aminebelkadi@gmail.com',
    pass: 'xboa tqvx efzi ttnq'
  }
});

// Stockage temporaire des codes de vérification
let verificationCodes = {};

// Route pour envoyer le code de vérification
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  const user = utilisateurs.find((u) => u.email === email);

  if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });

  // Générer un code de 6 chiffres
  const code = crypto.randomInt(100000, 999999).toString();
  verificationCodes[email] = code;

  // Envoyer l'email
  const mailOptions = {
    from: 'votre.email@gmail.com',
    to: email,
    subject: 'Réinitialisation du mot de passe',
    text: `Votre code de réinitialisation est : ${code}. Suivez le lien : http://localhost:3000/resetpass.html`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: 'Erreur lors de l\'envoi de l\'email' });
    }
    res.json({ message: 'Email de réinitialisation envoyé' });
  });
});

//Route reset-password
app.post('/reset-password', (req, res) => {
  const { code, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Les mots de passe ne correspondent pas' });
  }

  const email = Object.keys(verificationCodes).find((key) => verificationCodes[key] === code);
  if (!email) return res.status(400).json({ message: 'Code de vérification incorrect' });

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: 'Erreur lors du hachage du mot de passe' });

    utilisateurs = utilisateurs.map((user) =>
      user.email === email ? { ...user, password: hashedPassword } : user
    );

    // Mise à jour du fichier CSV
    const csvData = utilisateurs.map((u) => `${u.email},${u.password}`).join('\n');
    fs.writeFile('./data/utilisateurs.csv', csvData, (err) => {
      if (err) return res.status(500).json({ message: 'Erreur lors de la mise à jour du fichier' });

      delete verificationCodes[email]; // Suppression du code utilisé
      res.json({ message: 'Mot de passe mis à jour avec succès' });
    });
  });
});



app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
