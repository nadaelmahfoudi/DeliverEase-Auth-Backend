const express = require('express');
const { registerUser, verifyEmail, loginUser, verifyOtp, forgetPassword, resetPassword} = require('../controllers/userController');
const router = express.Router();


router.post('/register', registerUser);
router.get('/verify/:token', verifyEmail);
router.post('/login', loginUser);
router.post('/verify-otp', verifyOtp);
router.post('/forget-password', forgetPassword);
router.post('/reset-password', resetPassword);
module.exports = router;