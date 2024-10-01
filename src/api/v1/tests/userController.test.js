const nodemailer = require('nodemailer');
const User = require('../models/User');
const { registerUser, verifyEmail, loginUser, verifyOtp, forgetPassword, sendOtpEmail, resetPassword} = require('../controllers/userController');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mocking external modules
jest.mock('bcryptjs');
jest.mock('../models/User');
jest.mock('jsonwebtoken');
jest.mock('nodemailer', () => {
    return {
        createTransport: jest.fn().mockReturnValue({
            sendMail: jest.fn().mockResolvedValue(true), // Mock sendMail to resolve successfully
        }),
    };
});

jest.mock('../controllers/userController', () => ({
    ...jest.requireActual('../controllers/userController'), 
    sendOtpEmail: jest.fn() // Mock de la fonction sendOtpEmail
}));

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
            jwt.sign.mockReturnValue('testToken'); // Mocking JWT generation

            await registerUser(req, res);

            expect(User.findOne).toHaveBeenCalledWith({ email: req.body.email });
            expect(User.prototype.save).toHaveBeenCalled();
            expect(nodemailer.createTransport().sendMail).toHaveBeenCalled(); // Check if the email was sent
            expect(res.status).toHaveBeenCalledWith(201);
            expect(res.json).toHaveBeenCalledWith({ message: 'Utilisateur créé avec succès.', token: 'testToken' });
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

    describe('loginUser', () => {
        let req, res;
    
        beforeEach(() => {
            req = {
                body: {
                    email: 'test@example.com',
                    password: 'password123',
                },
            };
            res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn(),
            };
        });
    
        it('should return error if user is not found or not verified', async () => {
            User.findOne.mockResolvedValue(null);
    
            await loginUser(req, res);
    
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Utilisateur non trouvé ou non vérifié.' });
        });
    
        it('should return error if password does not match', async () => {
            User.findOne.mockResolvedValue({ email: 'test@example.com', password: 'hashedPassword', isVerified: true });
            bcryptjs.compare.mockResolvedValue(false);
    
            await loginUser(req, res);
    
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Identifiants invalides.' });
        });
    
        it('should return success and send OTP if user is found and password matches', async () => {
            const mockUser = {
                email: 'test@example.com',
                password: 'hashedPassword',
                isVerified: true,
                save: jest.fn(),
            };
    
            User.findOne.mockResolvedValue(mockUser);
            bcryptjs.compare.mockResolvedValue(true);
    
            await loginUser(req, res);
    
            expect(mockUser.save).toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ message: 'OTP envoyé à votre e-mail. Veuillez le saisir.' });
        });
    
        it('should handle exceptions and return a server error', async () => {
            User.findOne.mockRejectedValue(new Error('Database error'));
    
            await loginUser(req, res);
    
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ message: 'Erreur lors de la connexion.' });
        });
    });
    describe('verifyOtp', () => {
        let req, res;
    
        beforeEach(() => {
            req = {
                body: {
                    email: 'test@example.com',
                    otp: '123456',
                },
            };
            res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn(),
            };
        });
    
        it('should return error if user not found or OTP does not match', async () => {
            User.findOne.mockResolvedValue(null);
    
            await verifyOtp(req, res);
    
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'OTP invalide ou utilisateur non trouvé.' });
        });
    
        it('should return error if OTP is expired', async () => {
            User.findOne.mockResolvedValue({
                email: 'test@example.com',
                otp: '123456',
                otpExpires: Date.now() - 1000, // Expired OTP
            });
    
            await verifyOtp(req, res);
    
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'OTP expiré.' });
        });
    
        it('should authenticate user and return token if OTP is valid', async () => {
            const mockUser = {
                _id: 'user123',
                email: 'test@example.com',
                otp: '123456',
                otpExpires: Date.now() + 1000, // Valid OTP
                save: jest.fn(),
            };
    
            User.findOne.mockResolvedValue(mockUser);
            jwt.sign.mockReturnValue('validToken');
    
            await verifyOtp(req, res);
    
            expect(mockUser.save).toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ message: 'Authentifié avec succès', token: 'validToken' });
        });
    
        it('should handle exceptions and return a server error', async () => {
            User.findOne.mockRejectedValue(new Error('Database error'));
    
            await verifyOtp(req, res);
    
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ message: 'Erreur lors de la vérification de l’OTP.' });
        });
    });    

    describe('forgetPassword', () => {
        let req, res;
    
        beforeEach(() => {
            req = {
                body: {
                    email: 'test@example.com',
                },
            };
            res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn(),
            };
        });
    
        it("should send an OTP to the user's email if user is found", async () => {
            const mockUser = {
                email: 'test@example.com',
                otp: null,
                otpExpires: null,
                save: jest.fn().mockResolvedValue(), // Simulate save function
            };
        
            User.findOne.mockResolvedValue(mockUser); // Simulate finding the user
            sendOtpEmail.mockResolvedValue(true); // Ensure sendOtpEmail resolves successfully
        
            // Call forgetPassword function
            await forgetPassword(req, res);
        
            // Verify that the OTP was generated
            expect(mockUser.otp).toBeDefined();
            expect(mockUser.otpExpires).toBeDefined();
        
            // Verify that user.save() was called
            expect(mockUser.save).toHaveBeenCalled();
        
            // Verify that sendOtpEmail was called with the correct parameters
            expect(sendOtpEmail).toHaveBeenCalledWith(mockUser, mockUser.otp); // Ensure this line matches the function call
        
            // Check the response status and message
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({
                message: 'Un OTP a été envoyé à votre e-mail pour réinitialiser le mot de passe.',
            });
        });
        
        it('should return an error if the user is not found', async () => {
            User.findOne = jest.fn().mockResolvedValue(null); // Simulate user not found
    
            await forgetPassword(req, res);
    
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Utilisateur non trouvé.' });
        });
    
        it('should handle exceptions and return a server error', async () => {
            User.findOne = jest.fn().mockRejectedValue(new Error('Database error')); // Simulate an error
    
            await forgetPassword(req, res);
    
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ message: 'Erreur lors de la réinitialisation du mot de passe.' });
        });
    });


    describe('resetPassword', () => {
        let req, res, mockUser;
    
        beforeEach(() => {
            req = {
                body: {
                    email: 'test@example.com',
                    otp: '333691',
                    newPassword: 'newPassword123',
                },
            };
    
            res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn(),
            };
    
            mockUser = {
                email: 'test@example.com',
                otp: '333691',
                otpExpires: Date.now() + 10 * 60 * 1000, // OTP valid for 10 minutes
                password: 'oldPassword',
                save: jest.fn().mockResolvedValue(true), // Mock save function
            };
    
            User.findOne.mockResolvedValue(mockUser); // Mock User.findOne to return the mock user
        });
    
        afterEach(() => {
            jest.clearAllMocks(); // Clear mocks after each test
        });
    
        test('should reset the password successfully with valid OTP', async () => {
            await resetPassword(req, res);
    
            // Check that the password was hashed and saved
            expect(bcryptjs.hash).toHaveBeenCalledWith(req.body.newPassword, 10);
            expect(mockUser.password).toBe('hashedPassword'); // Ensure this matches your expectations
            expect(mockUser.otp).toBeNull();
            expect(mockUser.otpExpires).toBeNull();
            expect(mockUser.save).toHaveBeenCalled();
    
            // Check the response
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ message: 'Mot de passe réinitialisé avec succès.' });
        });
    
        test('should return an error if the user is not found', async () => {
            User.findOne.mockResolvedValue(null); // Mocking no user found
    
            await resetPassword(req, res);
    
            // Check the response
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'OTP invalide ou expiré.' });
        });
    
        test('should return an error if OTP is invalid', async () => {
            mockUser.otp = 'wrongOtp'; // Set a wrong OTP
    
            await resetPassword(req, res);
    
            // Check the response
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'OTP invalide ou expiré.' });
        });
    
        test('should return an error if OTP is expired', async () => {
            mockUser.otpExpires = Date.now() - 10 * 60 * 1000; // Set the OTP to be expired
    
            await resetPassword(req, res);
    
            // Check the response
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'OTP invalide ou expiré.' });
        });
    
        test('should handle server errors', async () => {
            User.findOne.mockRejectedValue(new Error('Database error')); // Simulate a database error
    
            await resetPassword(req, res);
    
            // Check the response
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ message: 'Erreur lors de la réinitialisation du mot de passe.' });
        });
    });
    
});
