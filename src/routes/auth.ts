import express from "express";
import {
	login,
	logout,
	refreshToken,
	register,
	sendMagicLink,
	setPassword,
	verifyMagicLink,
} from "../controllers/auth.controller";
import { authenticate } from "../middlewares/auth.middleware";
import { validateRequest } from "../middlewares/validation.middleware";
import { loginSchema, registerSchema } from "../validators/auth.validator";

/**
 * Routes that implement or require a form of
 * authentication or authorization.
 *
 * Pass `authenticate` or `authorize(requiredRole)` as middleware
 */
const router = express.Router();

router.get("/", (req, res) => {
	res.send("Healthscope Reader Authentication/Authorization Resources");
});

// Authentication routes
router.post("/register", validateRequest(registerSchema), register);
router.post("/login", validateRequest(loginSchema), login);
router.post("/refresh-token", refreshToken);
router.post("/logout", authenticate, logout);

// Magic link authentication to add to postman later
router.post("/magic-link", sendMagicLink);
router.get("/verify-magic-link", verifyMagicLink);
router.post("/set-password", authenticate, setPassword);

export default router;
