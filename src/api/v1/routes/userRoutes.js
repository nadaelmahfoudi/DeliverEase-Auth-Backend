const express = require('express');
const { registerUser, verifyEmail, loginUser, verifyOtp, forgetPassword} = require('../controllers/userController');
const router = express.Router();


router.post('/register', registerUser);
router.get('/verify/:token', verifyEmail);
router.post('/login', loginUser);
router.post('/verify-otp', verifyOtp);
router.post('/forget-password', forgetPassword);
module.exports = router;