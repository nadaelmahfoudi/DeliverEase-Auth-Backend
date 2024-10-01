// app.js
const express = require('express');
const userRoutes = require('./src/api/v1/routes/userRoutes');
const { connect } = require('./config/config'); // Assurez-vous d'importer la fonction connect

require('dotenv').config();

const app = express();
app.use(express.json()); // Pour parser le JSON

connect(); // Appelez la fonction connect pour établir la connexion à MongoDB

// Utilisation des routes
app.use('/api/v1/users', userRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
