import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username must be lowercase")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),

    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),

    body("fullName").trim(),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .isLength({ min: 3 })
      .withMessage("Password must be at least 3 characters long"),
  ];
};

const loginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Invalid email format"),

    body("username")
      .optional()
      .trim()
      .notEmpty()
      .withMessage("Username cannot be empty"),

    body("password").notEmpty().withMessage("Password is required"),

    body().custom((_, { req }) => {
      if (!req.body.email && !req.body.username) {
        throw new Error("Email or username is required");
      }
      return true;
    }),
  ];
};

const userChangeCurrentPasswordValidator = () => [
  body("oldPassword").notEmpty().withMessage("Old password is required"),
  body("newPassword").notEmpty().withMessage("New password is required"),
];

const userForgotPasswordValidator = () => [
  body("email")
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Email is invalid"),
];

const userResetForgotPasswordValidator = () => [
  body("newPassword").notEmpty().withMessage("Password is required"),
];

export {
  userRegisterValidator,
  loginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
