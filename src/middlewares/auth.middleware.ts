import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AccountModel } from "../models/users/account.model";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key"; // TODO: Move to config

export interface AuthRequest extends Request {
	user?: any;
}

export const authenticate = async (
	req: AuthRequest,
	res: Response,
	next: NextFunction
) => {
	try {
		const token = req.headers.authorization?.split(" ")[1];

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
