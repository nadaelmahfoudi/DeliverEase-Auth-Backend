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
    await user.save(); 

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
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email déjà utilisé !' });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            phoneNumber,
            address,
            role,
        });

        await newUser.save();

        await sendVerificationEmail(newUser);

        const token = jwt.sign(
            { id: newUser._id, email: newUser.email },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        res.status(201).json({ message: 'Utilisateur créé avec succès.', token });
    } catch (error) {
        console.error("Error during user creation:", error);
        res.status(500).json({ message: 'Erreur lors de la création de l’utilisateur.', error: error.message });
    }      
};


exports.verifyEmail = async (req, res) => {
    const { token } = req.params;

    try {
        // Chercher l'utilisateur par le token de vérification
        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            return res.status(404).json({ message: 'Token de vérification invalide ou expiré.' });
        }

        // Activer l'utilisateur
        user.isVerified = true;
        user.verificationToken = undefined; 
        await user.save(); 

        return res.redirect('http://localhost:5173/login'); 
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
        console.log("Utilisateur trouvé :", user); // Debug

        if (!user) {
            return res.status(400).json({ message: 'Utilisateur non trouvé.' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Utilisateur non vérifié.' });
        }

        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Identifiants invalides.' });
        }

        // Vérifiez le statut du premier login ou si l'OTP a expiré
        if (user.isFirstLogin || (user.otpExpires && user.otpExpires < Date.now())) {
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            user.otp = otp;
            user.otpExpires = Date.now() + 5 * 60 * 1000; // L'OTP expire dans 5 minutes
            user.isFirstLogin = false; // Marquer comme non premier login

            await user.save(); // Enregistrez les changements
            await sendOtpEmail(user, otp);

            return res.status(200).json({
                message: 'Connexion réussie, OTP envoyé.',
                user: { id: user._id, email: user.email, isVerified: user.isVerified, isFirstLogin: user.isFirstLogin },
                // Pas de token ici, car vous devez vérifier l'OTP
                requiresOtp: true // Indique que l'OTP est requis
            });
        }

        // Si l'utilisateur est déjà connecté et a un OTP valide
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        return res.status(200).json({
            message: 'Connexion réussie.',
            user: { id: user._id, email: user.email, isVerified: user.isVerified, isFirstLogin: user.isFirstLogin },
            token,
            requiresOtp: false // Indique que l'OTP n'est pas requis
        });

    } catch (error) {
        console.error("Erreur lors de la connexion :", error);
        return res.status(500).json({ message: 'Erreur lors de la connexion.' });
    }
};


// Vérification de l'OTP
exports.verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ message: 'Email ou OTP manquant.' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Utilisateur non trouvé.' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ message: 'OTP invalide.' });
        }
        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP expiré. Veuillez demander un nouvel OTP.' });
        }        

        // Authentification réussie, générez le token JWT
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // Réinitialiser l'OTP et son expiration dans la base de données
        user.otp = null; 
        user.otpExpires = null; 
        user.isFirstLogin = false;
        await user.save();

        // Réponse de succès
        res.status(200).json({ message: 'Authentifié avec succès', token });
    } catch (error) {
        console.error("Erreur lors de la vérification de l'OTP :", error);
        res.status(500).json({ message: 'Erreur lors de la vérification de l’OTP.' });
    }
};


// New function to resend OTP
exports.resendOtp = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user || !user.isVerified) {
            return res.status(400).json({ message: 'Utilisateur non trouvé ou non vérifié.' });
        }

        // Generate new OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 5 * 60 * 1000; // OTP expire dans 5 minutes
        
        await user.save();
        await sendOtpEmail(user, otp); // Send the OTP by email

        res.status(200).json({ message: 'Un nouvel OTP a été envoyé.' });
    } catch (error) {
        console.error("Erreur lors de l'envoi de l'OTP :", error);
        res.status(500).json({ message: 'Erreur lors de l\'envoi de l\'OTP.' });
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
