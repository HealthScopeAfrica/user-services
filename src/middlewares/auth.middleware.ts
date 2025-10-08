import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AccountModel } from "../models/users/account.model";

const JWT_SECRET = process.env.JWT_SECRET || "secret-key";

// Use your existing AuthRequest interface
export interface AuthRequest extends Request {
	user?: any;
	file?: Express.Multer.File;
	files?:
		| Express.Multer.File[]
		| { [fieldname: string]: Express.Multer.File[] };
}

// Your existing authenticate middleware (keeping as-is)
export const authenticate = async (
	req: AuthRequest,
	res: Response,
	next: NextFunction
) => {
	try {
		const authHeader = req.headers.authorization;
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			return res.status(401).json({ message: "Bearer token required" });
		}

		const token = authHeader.split(" ")[1];

		if (!token) {
			return res.status(401).json({ message: "Authentication required" });
		}

		const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
		const user = await AccountModel.findById(decoded.userId);

		if (!user || user.status !== "enabled") {
			return res
				.status(401)
				.json({ message: "Invalid or disabled account" });
		}

		req.user = user;
		next();
	} catch (error) {
		return res.status(401).json({ message: "Invalid token" });
	}
};

// Your existing authorize middleware (keeping as-is)
export const authorize = (...roles: string[]) => {
	return (req: AuthRequest, res: Response, next: NextFunction) => {
		if (!req.user) {
			return res.status(401).json({ message: "Authentication required" });
		}

		if (!roles.includes(req.user.role)) {
			return res.status(403).json({ message: "Unauthorized access" });
		}

		next();
	};
};

// NEW: Optional authentication for public+private endpoints
export const optionalAuth = async (
	req: AuthRequest,
	res: Response,
	next: NextFunction
) => {
	try {
		const authHeader = req.headers.authorization;

		if (authHeader && authHeader.startsWith("Bearer ")) {
			const token = authHeader.split(" ")[1];

			if (token) {
				const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
				const user = await AccountModel.findById(decoded.userId);

				if (user && user.status === "enabled") {
					req.user = user;
				}
			}
		}

		// Continue regardless of auth status
		next();
	} catch (error) {
		// If token is invalid, just continue without user
		next();
	}
};
