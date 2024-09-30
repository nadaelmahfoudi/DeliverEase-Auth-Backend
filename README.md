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

- **Description**: Authenticate the user and send an OTP to the registered email.
- **Request Body**:
  - `email` (string, required): The user's email address.
  - `password` (string, required): The user's password.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "OTP envoyé à votre e-mail. Veuillez le saisir."
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
      "message": "Erreur lors de la connexion.",
      "error": "error_message"
    }
    ```

### 4. Verify OTP

**POST** `/verify-otp`

- **Description**: Verify the OTP sent to the user's email.
- **Request Body**:
  - `email` (string, required): The user's email address.
  - `otp` (string, required): The OTP received via email.

- **Response**:
  - **200 OK**:
    ```json
    {
      "message": "Authentifié avec succès",
      "token": "your_jwt_token"
    }
    ```
  - **400 Bad Request**:
    ```json
    {
      "message": "OTP invalide ou utilisateur non trouvé."
    }
    ```
  - **500 Internal Server Error**:
    ```json
    {
      "message": "Erreur lors de la vérification de l’OTP.",
      "error": "error_message"
    }
    ```

### 5. Forget Password

**POST** `/forget-password`

- **Description**: Send an OTP to the user's email for password recovery.
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
      "message": "Erreur lors de la réinitialisation du mot de passe.",
      "error": "error_message"
    }
    ```

### 6. Reset Password

**POST** `/reset-password`

- **Description**: Reset the user's password using the OTP.
- **Request Body**:
  - `email` (string, required): The user's email address.
  - `otp` (string, required): The OTP received via email.
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
      "message": "Erreur lors de la réinitialisation du mot de passe.",
      "error": "error_message"
    }
    ```

## Error Handling

All error responses will include a message and, when applicable, an error detail. The status codes used include:
- **400 Bad Request**: Client-side errors, such as invalid data or requests.
- **404 Not Found**: Resource not found, such as an invalid verification token.
- **500 Internal Server Error**: Server-side errors.

## Environment Variables

Make sure to set the following environment variables in your `.env` file:

EMAIL_USER=your_email@gmail.com 
EMAIL_PASS=your_email_password 
JWT_SECRET=your_jwt_secret


## Conclusion

This API provides a robust user authentication system with email verification and OTP functionalities, ensuring secure access for users.
