# Django REST Framework JWT Authentication

This project provides a simple JWT-based authentication system using Django REST Framework (DRF).  
It includes user registration, login, profile management, password change, and password reset via email.

---

## API Endpoints

### 1. User Registration
**URL:** `/register/`  
**Method:** `POST`  
**Description:** Register a new user.

---

### 2. User Login
**URL:** `/login/`  
**Method:** `POST`  
**Description:** Authenticate user and return JWT tokens (access & refresh).

---

### 3. User Profile
**URL:** `/profile/`  
**Method:** `GET`  
**Authentication:** Bearer Token (JWT)  
**Description:** Fetch details of the logged-in user.

---

### 4. Change Password
**URL:** `/change-password/`  
**Method:** `POST`  
**Authentication:** Bearer Token (JWT)  
**Description:** Change password for the logged-in user.

---

### 5. Send Password Reset Email
**URL:** `/password-reset-mail/`  
**Method:** `POST`  
**Description:** Send a password reset link to the user’s email.

---

### 6. Reset Password
**URL:** `/password-reset/<uid>/<token>/`  
**Method:** `POST`  
**Description:** Reset user password using UID and token.

---

## Authentication
- JWT (JSON Web Token) is used for authentication.  
- Use `Authorization: Bearer <access_token>` in headers for protected routes.

---

## Tech Stack
- Django
- Django REST Framework
- SimpleJWT
