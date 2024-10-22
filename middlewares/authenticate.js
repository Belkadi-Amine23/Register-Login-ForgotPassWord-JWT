const jwt = require('jsonwebtoken');
const JWT_SECRET = 'votre_secret_pour_signer_les_jwt';

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Accès refusé' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token invalide' });
    req.user = user;
    next();
  });
}

module.exports = authenticateToken;
