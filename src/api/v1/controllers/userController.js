require('dotenv').config();
const User = require('../models/User');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Configure Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS, 
    },
});

// Function to send verification email
const sendVerificationEmail = async (user) => {
    const token = crypto.randomBytes(32).toString('hex'); 
    user.verificationToken = token; 
    await user.save(); // Save the token to the user model

    const verificationUrl = `http://localhost:5000/api/v1/users/verify/${token}`;
    
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Vérifiez votre e-mail',
        text: `Cliquez sur ce lien pour vérifier votre e-mail: ${verificationUrl}`,
    };

    await transporter.sendMail(mailOptions); // Send the email
};



// Function to send OTP email
const sendOtpEmail = async (user, otp) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Votre code OTP',
        text: `Votre code OTP est : ${otp}`,
    };

    await transporter.sendMail(mailOptions);
};



// Register User Function
exports.registerUser = async (req, res) => {
    const { name, email, password, phoneNumber, address, role } = req.body;

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email déjà utilisé !' });
        }

        // Hash the password
        const hashedPassword = await bcryptjs.hash(password, 10);

        // Create a new user
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            phoneNumber,
            address,
            role,
        });

        await newUser.save(); // Save the new user to the database

        // Send verification email
        await sendVerificationEmail(newUser); // Ensure this function is called

        // Generate a JWT token
        const token = jwt.sign(
            { id: newUser._id, email: newUser.email },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' } // Token expiration
        );

        res.status(201).json({ message: 'Utilisateur créé avec succès.', token });
    } catch (error) {
        console.error("Error during user creation:", error); // Log the full error message
        res.status(500).json({ message: 'Erreur lors de la création de l’utilisateur.', error: error.message });
    }      
};

// Email Verification Function
exports.verifyEmail = async (req, res) => {
    const { token } = req.params;

    try {
        // Check if a user with this verification token exists
        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            return res.status(404).json({ message: 'Token de vérification invalide ou expiré.' });
        }

        // Activate the user
        user.isVerified = true; 
        user.verificationToken = undefined; // Clear the verification token
        await user.save(); // Save the updated user

        res.status(200).json({ message: 'E-mail vérifié avec succès !' });
    } catch (error) {
        console.error("Erreur lors de la vérification de l'e-mail:", error); 
        res.status(500).json({ message: 'Erreur lors de la vérification de l’e-mail.', error: error.message });
    }
};


// Login User Function
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || !user.isVerified) {
            return res.status(400).json({ message: 'Utilisateur non trouvé ou non vérifié.' });
        }

        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Identifiants invalides.' });
        }

        // Generate and send OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit OTP
        user.otp = otp; // Store OTP in User model
        user.otpExpires = Date.now() + 5 * 60 * 1000; // Set expiration time for OTP
        await user.save();

        await sendOtpEmail(user, otp); // Send email with OTP

        res.status(200).json({ message: 'OTP envoyé à votre e-mail. Veuillez le saisir.' });
    } catch (error) {
        console.error("Erreur lors de la connexion :", error);
        res.status(500).json({ message: 'Erreur lors de la connexion.' });
    }
};
exports.verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email });
        
        // Log the user and OTP for debugging
        console.log("User found:", user);
        console.log("Provided OTP:", otp);
        console.log("Stored OTP:", user.otp);
        
        if (!user || user.otp !== otp) {
            return res.status(400).json({ message: 'OTP invalide ou utilisateur non trouvé.' });
        }

        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP expiré.' });
        }

        // Authenticate user and generate JWT
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.otp = null; // Reset OTP
        user.otpExpires = null; // Reset OTP expiration
        await user.save();

        res.status(200).json({ message: 'Connexion réussie.', token });
    } catch (error) {
        console.error("Erreur lors de la vérification de l'OTP :", error);
        res.status(500).json({ message: 'Erreur lors de la vérification de l’OTP.' });
    }
};




// Forget Password Function
exports.forgetPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Utilisateur non trouvé.' });
        }

        // Générer un OTP pour la réinitialisation
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes d'expiration
        await user.save();

        // Envoyer l'OTP par e-mail
        await sendOtpEmail(user, otp);

        res.status(200).json({ message: 'Un OTP a été envoyé à votre e-mail pour réinitialiser le mot de passe.' });
    } catch (error) {
        console.error("Erreur lors de la réinitialisation du mot de passe :", error);
        res.status(500).json({ message: 'Erreur lors de la réinitialisation du mot de passe.' });
    }
};


// Reset Password Function
exports.resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP invalide ou expiré.' });
        }

        // Hacher le nouveau mot de passe
        const hashedPassword = await bcryptjs.hash(newPassword, 10);
        user.password = hashedPassword;
        user.otp = null;
        user.otpExpires = null;
        await user.save();

        res.status(200).json({ message: 'Mot de passe réinitialisé avec succès.' });
    } catch (error) {
        console.error("Erreur lors de la réinitialisation du mot de passe :", error);
        res.status(500).json({ message: 'Erreur lors de la réinitialisation du mot de passe.' });
    }
};
