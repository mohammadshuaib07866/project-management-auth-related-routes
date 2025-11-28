import express from "express";
import {
  registeredUser,
  loginUser,
  logoutUser,
  getCurrentUser,
  refreshAccessToken,
  verifyEmail,
  resendEmailVerification,
  forgotPasswordRequest,
  resetForgotPassword,
  changeCurrentPassword,
} from "../controllers/auth.controller.js";

import {
  userRegisterValidator,
  loginValidator,
  userForgotPasswordValidator,
  userChangeCurrentPasswordValidator,
  userResetForgotPasswordValidator,
} from "../validation/index.js";

import { validate } from "../middlewares/validator.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = express.Router();

/* -------------------------------------------------------
   UNPROTECTED ROUTES
------------------------------------------------------- */
router.post("/register", userRegisterValidator(), validate, registeredUser);
router.post("/login", loginValidator(), validate, loginUser);
router.get("/verify-email/:verificationToken", verifyEmail);
router.post("/refresh-token", refreshAccessToken);

router.post(
  "/forgot-password",
  userForgotPasswordValidator(),
  validate,
  forgotPasswordRequest
);

router.post(
  "/reset-password/:resetToken",
  userResetForgotPasswordValidator(),
  validate,
  resetForgotPassword
);

/* -------------------------------------------------------
   PROTECTED ROUTES (require JWT)
------------------------------------------------------- */
router.post("/logout", verifyJWT, logoutUser);
router.get("/current-user", verifyJWT, getCurrentUser);

router.post(
  "/change-password",
  verifyJWT,
  userChangeCurrentPasswordValidator(),
  validate,
  changeCurrentPassword
);

// resend verification
router.post("/resend-email-verification", verifyJWT, resendEmailVerification);

export default router;
