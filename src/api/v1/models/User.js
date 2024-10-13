const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phoneNumber: { type: String, required: false },
  address: { type: String },
  role: { type: String, enum: ['manager', 'client', 'livreur'], default: 'client' },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  otp: {type: String,default: null,},
  otpExpires: {type: Date, default: null,},
  isFirstLogin: { type: Boolean, default: true },
});

module.exports = mongoose.model('User', userSchema);
