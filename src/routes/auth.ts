import express from 'express';
import { register, login } from "../controllers/auth.controller";
import { authenticate, authorize, AuthRequest } from '../middlewares/auth.middleware';
import { validateRequest } from "../middlewares/validation.middleware";
import { registerSchema, loginSchema } from "../validators/auth.validator";

/**
 * Routes that implement or require a form of
 * authentication or authorization.
 *
 * Pass `authenticate` or `authorize(requiredRole)` as middleware
 */
const router = express.Router();

// Auth routes
router.post("/register", validateRequest(registerSchema), register);
router.post("/login", validateRequest(loginSchema), login);

// Protected route example
router.get('/me', authenticate, (req: AuthRequest, res) => {
  res.json({ user: req.user });
});

// Role-specific route example
router.get('/admin-only', authenticate, authorize('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

export default router;
