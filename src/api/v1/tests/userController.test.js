const nodemailer = require('nodemailer');
const User = require('../models/User'); // Ensure this path is correct
const { registerUser, verifyEmail } = require('../controllers/userController');

// Mocking nodemailer
jest.mock('nodemailer', () => {
    return {
        createTransport: jest.fn().mockReturnValue({
            sendMail: jest.fn().mockResolvedValue(true), // Mock sendMail to resolve successfully
        }),
    };
});

// Mocking User model
jest.mock('../models/User');

describe('User Controller', () => {
    describe('registerUser', () => {
        it('should register a new user successfully', async () => {
            const req = {
                body: {
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'password123',
                    phoneNumber: '1234567890',
                    address: '123 Test St',
                    role: 'client'
                }
            };
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            };

            User.findOne.mockResolvedValue(null); // Mocking user not found
            User.prototype.save.mockResolvedValue(); // Mocking save success

            await registerUser(req, res);

            expect(User.findOne).toHaveBeenCalledWith({ email: req.body.email });
            expect(User.prototype.save).toHaveBeenCalled();
            expect(nodemailer.createTransport().sendMail).toHaveBeenCalled(); // Check if the email was sent
            expect(res.status).toHaveBeenCalledWith(201);
            expect(res.json).toHaveBeenCalledWith({ message: 'Utilisateur créé avec succès.', token: expect.any(String) });
        });

        it('should return an error if email is already in use', async () => {
            const req = {
                body: {
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'password123',
                    phoneNumber: '1234567890',
                    address: '123 Test St',
                    role: 'client'
                }
            };
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            };

            User.findOne.mockResolvedValue({}); // Mocking user found

            await registerUser(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Email déjà utilisé !' });
        });

        it('should return a server error if an exception occurs', async () => {
            const req = {
                body: {
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'password123',
                    phoneNumber: '1234567890',
                    address: '123 Test St',
                    role: 'client'
                }
            };
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            };

            User.findOne.mockRejectedValue(new Error('Database error')); // Mocking database error

            await registerUser(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ message: 'Erreur lors de la création de l’utilisateur.', error: 'Database error' });
        });
    });

    describe('verifyEmail', () => {
        it('should verify a user email successfully', async () => {
            const req = {
                params: {
                    token: 'validToken'
                }
            };
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            };

            const user = {
                isVerified: false,
                verificationToken: 'validToken',
                save: jest.fn().mockResolvedValue()
            };

            User.findOne.mockResolvedValue(user); // Mocking user found

            await verifyEmail(req, res);

            expect(user.isVerified).toBe(true);
            expect(user.verificationToken).toBeUndefined(); // Token should be cleared
            expect(user.save).toHaveBeenCalled(); // Ensure user.save() was called
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ message: 'E-mail vérifié avec succès !' });
        });

        it('should return an error if the token is invalid', async () => {
            const req = {
                params: {
                    token: 'invalidToken'
                }
            };
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            };

            User.findOne.mockResolvedValue(null); // Mocking no user found

            await verifyEmail(req, res);

            expect(res.status).toHaveBeenCalledWith(404);
            expect(res.json).toHaveBeenCalledWith({ message: 'Token de vérification invalide ou expiré.' });
        });

        it('should return a server error if an exception occurs', async () => {
            const req = {
                params: {
                    token: 'someToken'
                }
            };
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            };

            User.findOne.mockRejectedValue(new Error('Database error')); // Mocking database error

            await verifyEmail(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ message: 'Erreur lors de la vérification de l’e-mail.', error: 'Database error' });
        });
    });
});
