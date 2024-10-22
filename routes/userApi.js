const express = require('express');
const router = express.Router();

// Exemple d'endpoint protégé
router.get('/', (req, res) => {
  res.json({ message: 'Bienvenue dans l\'API protégée', user: req.user });
});

module.exports = router;
