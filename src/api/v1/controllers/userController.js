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
