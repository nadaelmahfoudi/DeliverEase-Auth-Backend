// config/config.js
const mongoose = require('mongoose');
require('dotenv').config();

const connect = () => {
  mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
  });
};

module.exports = {
  connect,
  MONGODB_URI: process.env.MONGODB_URI,
  PORT: process.env.PORT || 5000,
};
