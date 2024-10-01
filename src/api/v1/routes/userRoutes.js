const express = require('express');
const { registerUser, verifyEmail, loginUser, verifyOtp } = require('../controllers/userController');
const router = express.Router();


router.post('/register', registerUser);
router.get('/verify/:token', verifyEmail);
router.post('/login', loginUser);
router.post('/verify-otp', verifyOtp);

module.exports = router;