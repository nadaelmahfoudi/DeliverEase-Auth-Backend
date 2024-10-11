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

        if (!user || !user.isVerified) {
            return res.status(400).json({ message: 'Utilisateur non trouvé ou non vérifié.' });
        }

        const isMatch = await bcryptjs.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Identifiants invalides.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
        user.otp = otp; 
        user.otpExpires = Date.now() + 5 * 60 * 1000; // OTP expire dans 5 minutes
        
        await user.save();  // Sauvegarder l'OTP et son expiration dans la base de données
        await sendOtpEmail(user, otp);  // Envoyer l'OTP par e-mail
        
        // Envoyer la réponse au client
        res.status(200).json({ 
            message: 'Connexion réussie, OTP envoyé.', 
            user: { id: user._id, email: user.email, isVerified: user.isVerified },
            token: jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' })  // Génération du token JWT
        });
        
    } catch (error) {
        console.error("Erreur lors de la connexion :", error);
        res.status(500).json({ message: 'Erreur lors de la connexion.' });
    }
};




exports.verifyOtp = async (req, res) => {
    console.log('Données reçues :', req.body); // Ajouter ceci pour voir les données reçues par le serveur
  
    const { email, otp } = req.body;
  
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email ou OTP manquant.' });
    }

    try {
        // Vérification de l'existence de l'utilisateur
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Utilisateur non trouvé.' });
        }

        // Vérification de l'OTP
        if (user.otp !== otp) {
            return res.status(400).json({ message: 'OTP invalide.' });
        }

        // Vérification de l'expiration de l'OTP
        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP expiré.' });
        }

        // Authentification réussie, génération du token JWT
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // Réinitialisation de l'OTP et de son expiration dans la base de données
        user.otp = null; 
        user.otpExpires = null; 
        await user.save();

        // Réponse avec succès
        res.status(200).json({ message: 'Authentifié avec succès', token });
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
