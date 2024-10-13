# DeliverEase-Auth-Backend
# API Documentation

## Introduction

This API provides user authentication functionalities, including registration, email verification, login, OTP verification, password recovery, and password reset. It utilizes JWT for session management and Nodemailer for email notifications.

## Base URL
http://localhost:5000/api/v1/users




## Endpoints

### 1. Register User

**POST** `/register`

- **Description**: Register a new user and send a verification email.
- **Request Body**:
  - `name` (string, required): The user's full name.
  - `email` (string, required): The user's email address.
  - `password` (string, required): The user's password.
  - `phoneNumber` (string, optional): The user's phone number.
  - `address` (string, optional): The user's address.
  - `role` (string, optional): The user's role (e.g., admin, user).

- **Response**:
  - **201 Created**:
    ```json
    {
      "message": "Utilisateur créé avec succès.",
      "token": "your_jwt_token"
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "Email déjà utilisé !"
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la création de l’utilisateur.",
      "error": "error_message"
    }
    ```

### 2. Verify Email

**GET** `/verify/:token`

- **Description**: Verify the user's email using the token sent during registration.
- **URL Parameters**:
  - `token` (string, required): The verification token sent to the user's email.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "E-mail vérifié avec succès !"
    }
    ```
  - **404 Not Found**:
    ```json
    {
      "message": "Token de vérification invalide ou expiré."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la vérification de l’e-mail.",
      "error": "error_message"
    }
    ```

### 3. Login User

**POST** `/login`

- **Description**: Authenticate a user and return a JWT.
- **Request Body**:
  - `email` (string, required): The user's email address.
  - `password` (string, required): The user's password.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "Connexion réussie.",
      "user": {
        "id": "user_id",
        "email": "user_email",
        "isVerified": true,
        "isFirstLogin": false
      },
      "token": "your_jwt_token",
      "requiresOtp": false
    }
    ```
  - **200 OK (Requires OTP)**:
    ```json
    {
      "message": "Connexion réussie, OTP envoyé.",
      "user": {
        "id": "user_id",
        "email": "user_email",
        "isVerified": true,
        "isFirstLogin": true
      },
      "requiresOtp": true
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "Utilisateur non trouvé."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la connexion."
    }
    ```

### 4. Verify OTP

**POST** `/verify-otp`

- **Description**: Verify the OTP sent to the user's email.
- **Request Body**:
  - `email` (string, required): The user's email address.
  - `otp` (string, required): The OTP code.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "Authentifié avec succès.",
      "token": "your_jwt_token"
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "OTP invalide ou expiré."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la vérification de l’OTP."
    }
    ```

### 5. Resend OTP

**POST** `/resend-otp`

- **Description**: Resend a new OTP to the user's email.
- **Request Body**:
  - `email` (string, required): The user's email address.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "Un nouvel OTP a été envoyé."
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "Utilisateur non trouvé ou non vérifié."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de l'envoi de l'OTP."
    }
    ```

### 6. Forget Password

**POST** `/forget-password`

- **Description**: Send an OTP to the user's email for password reset.
- **Request Body**:
  - `email` (string, required): The user's email address.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "Un OTP a été envoyé à votre e-mail pour réinitialiser le mot de passe."
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "Utilisateur non trouvé."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la réinitialisation du mot de passe."
    }
    ```

### 7. Reset Password

**POST** `/reset-password`

- **Description**: Reset the user's password using the OTP.
- **Request Body**:
  - `email` (string, required): The user's email address.
  - `otp` (string, required): The OTP sent to the email.
  - `newPassword` (string, required): The new password.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "Mot de passe réinitialisé avec succès."
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "OTP invalide ou expiré."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la réinitialisation du mot de passe."
    }
    ```

---

## Environment Variables

- `EMAIL_USER`: The email address used to send emails.
- `EMAIL_PASS`: The password for the email address.
- `JWT_SECRET`: The secret key for signing JWT tokens.
- `PORT`: The port on which the server runs.

---

## Error Handling

All errors are returned in the following format:
```json
{
  "message": "Description of the error.",
  "error": "Detailed error message (if available)."
}

### Installation

1. Clone the repository.
   ```bash
   git clone https://github.com/your-username/DeliverEase-Auth-Backend.git
2. Navigate into the project directory.
   ```bash
   cd DeliverEase-Auth-Backend
3. Install dependencies using:
   ```bash
   npm install
4. Run the server:
   ```bash
   npm start


## Conclusion

This API provides a robust user authentication system with email verification and OTP functionalities, ensuring secure access for users.
