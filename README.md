# Project Management Auth API

This repository contains authentication-related routes for a **Project Management System**.  
The backend is built using **Node.js**, **Express**, and **MongoDB**, with **JWT authentication** and **email verification**.

---

## Base URL


---

## Table of Contents

1. [Unsecured Routes](#unsecured-routes)
2. [Secured Routes](#secured-routes)
3. [Request/Response Examples](#requestresponse-examples)
4. [Middlewares](#middlewares)
5. [Setup Instructions](#setup-instructions)
6. [Testing](#testing)
7. [Author](#author)

---

## Unsecured Routes

These routes do **not require authentication**.

| Route | Method | Description | Body/Params |
|-------|--------|-------------|-------------|
| `/auth/register` | POST | Register a new user | `{ username, fullName, email, password }` |
| `/auth/login` | POST | Login with email/username and password | `{ email?, username?, password }` |
| `/auth/verify-email/:verificationToken` | GET | Verify a user's email | `verificationToken` in URL |
| `/auth/refresh-token` | POST | Refresh access and refresh tokens | `{ refreshToken? }` |
| `/auth/forgot-password` | POST | Request password reset email | `{ email }` |
| `/auth/reset-password/:resetToken` | POST | Reset password using token | `{ newPassword }` |

---

## Secured Routes

These routes **require JWT authentication**.

| Route | Method | Description | Body/Params |
|-------|--------|-------------|-------------|
| `/auth/logout` | POST | Logout user and clear refresh tokens | No body |
| `/auth/current-user` | GET | Get current logged-in user details | No body |
| `/auth/change-password` | POST | Change password for logged-in user | `{ oldPassword, newPassword }` |
| `/auth/resend-email-verification` | POST | Resend email verification to user | No body |

---

## Request/Response Examples

### 1. Register User

**POST /auth/register**

**Request Body:**

```json
{
  "username": "john_doe",
  "fullName": "John Doe",
  "email": "john@example.com",
  "password": "strongpassword123"
}
