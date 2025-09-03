import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { AuthRequest } from "../middlewares/auth.middleware";
import { AccountModel } from "../models/users/account.model";
import { ReaderProfileModel } from "../models/users/reader-profile.model";

const JWT_SECRET = process.env.JWT_SECRET || "secret-key";
const REFRESH_TOKEN_SECRET =
	process.env.REFRESH_TOKEN_SECRET || "refresh-secret-key";
const ACCESS_TOKEN_EXPIRY = "15m"; // 15 minutes
const REFRESH_TOKEN_EXPIRY = "7d"; // 7 days
const MAGIC_LINK_EXPIRY = "10m"; // 10 minutes

interface TokenPayload {
	userId: string;
	type?: "access" | "refresh" | "magic";
	email?: string;
}

const generateTokens = (userId: string) => {
	const accessToken = jwt.sign(
		{ userId, type: "access" } as TokenPayload,
		JWT_SECRET,
		{ expiresIn: ACCESS_TOKEN_EXPIRY }
	);
	const refreshToken = jwt.sign(
		{ userId, type: "refresh" } as TokenPayload,
		REFRESH_TOKEN_SECRET,
		{ expiresIn: REFRESH_TOKEN_EXPIRY }
	);
	return { accessToken, refreshToken };
};

const generateMagicLink = (email: string) => {
	const token = jwt.sign(
		{ email, type: "magic" } as TokenPayload,
		JWT_SECRET,
		{ expiresIn: MAGIC_LINK_EXPIRY }
	);
	// In production, this should be your frontend URL
	return `http://localhost:3000/auth/verify-magic-link?token=${token}`;
};

export const register = async (req: Request, res: Response) => {
	try {
		const { email, password, username, firstName, lastName } = req.body;

		// check for user
		const existingUser = await AccountModel.findOne({ email });
		if (existingUser) {
			return res.status(400).json({ message: "Email already registered" });
		}

		// Hash password
		const passwordHash = await bcrypt.hash(password, 10);

		// Create account
		const account = await AccountModel.create({
			email,
			passwordHash,
			role: "reader",
			username,
			status: "enabled",
		});

		// Create reader profile
		await ReaderProfileModel.create({
			accountId: account._id,
			firstName,
			lastName,
		});

		// Generate JWT
		const token = jwt.sign({ userId: account._id }, JWT_SECRET, {
			expiresIn: "24h",
		});

		res.status(201).json({
			message: "Registration successful",
			token,
			user: {
				id: account._id,
				email: account.email,
				role: account.role,
				username: account.username,
			},
		});
	} catch (error) {
		console.error("Registration error:", error);
		res.status(500).json({ message: "Error during registration" });
	}
};

export const login = async (req: Request, res: Response) => {
	try {
		const { email, password } = req.body;

		// Find user
		const account = await AccountModel.findOne({ email });
		if (!account || !account.passwordHash) {
			return res.status(401).json({ message: "Invalid credentials" });
		}

		// Check password
		const isValidPassword = await bcrypt.compare(
			password,
			account.passwordHash
		);
		if (!isValidPassword) {
			return res.status(401).json({ message: "Invalid credentials" });
		}

		if (account.status !== "enabled") {
			return res.status(403).json({ message: "This account is disabled" });
		}

		// Update last login
		account.lastLoginAt = new Date();
		await account.save();

		// Generate access and refresh tokens
		const { accessToken, refreshToken } = generateTokens(
			account._id.toString()
		);

		// Store refresh token hash in database
		const refreshTokenHash = crypto
			.createHash("sha256")
			.update(refreshToken)
			.digest("hex");
		account.refreshTokens = account.refreshTokens || [];
		account.refreshTokens.push(refreshTokenHash);
		await account.save();

		res.json({
			message: "Login successful",
			accessToken,
			refreshToken,
			user: {
				id: account._id,
				email: account.email,
				role: account.role,
				username: account.username,
			},
		});
	} catch (error) {
		console.error("Login error:", error);
		res.status(500).json({ message: "Error during login" });
	}
};

export const logout = async (req: AuthRequest, res: Response) => {
	try {
		const refreshToken = req.body.refreshToken;
		if (!refreshToken) {
			return res.status(400).json({ message: "Refresh token required" });
		}

		// Remove refresh token from database
		const refreshTokenHash = crypto
			.createHash("sha256")
			.update(refreshToken)
			.digest("hex");
		await AccountModel.updateOne(
			{ _id: req.user?.userId },
			{ $pull: { refreshTokens: refreshTokenHash } }
		);

		res.json({ message: "Logged out successfully" });
	} catch (error) {
		console.error("Logout error:", error);
		res.status(500).json({ message: "Error during logout" });
	}
};

export const refreshToken = async (req: Request, res: Response) => {
	try {
		const { refreshToken } = req.body;
		if (!refreshToken) {
			return res.status(400).json({ message: "Refresh token required" });
		}

		// Verify refresh token
		const payload = jwt.verify(
			refreshToken,
			REFRESH_TOKEN_SECRET
		) as TokenPayload;
		if (payload.type !== "refresh") {
			return res.status(401).json({ message: "Invalid refresh token" });
		}

		// Check if refresh token is in database
		const refreshTokenHash = crypto
			.createHash("sha256")
			.update(refreshToken)
			.digest("hex");
		const account = await AccountModel.findOne({
			_id: payload.userId,
			refreshTokens: refreshTokenHash,
		});

		if (!account) {
			return res.status(401).json({ message: "Invalid refresh token" });
		}

		// Generate new access token
		const accessToken = jwt.sign(
			{ userId: account._id, type: "access" } as TokenPayload,
			JWT_SECRET,
			{
				expiresIn: ACCESS_TOKEN_EXPIRY,
			}
		);

		res.json({ accessToken });
	} catch (error) {
		console.error("Refresh token error:", error);
		res.status(401).json({ message: "Invalid refresh token" });
	}
};

export const sendMagicLink = async (req: Request, res: Response) => {
	try {
		const { email } = req.body;
		const account = await AccountModel.findOne({ email });

		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		const magicLink = generateMagicLink(email);
		// TODO: Send magic link via email service
		// For development, we'll just return it
		res.json({
			message: "Magic link sent successfully",
			magicLink, // Remove this in production
		});
	} catch (error) {
		console.error("Magic link error:", error);
		res.status(500).json({ message: "Error sending magic link" });
	}
};

export const verifyMagicLink = async (req: Request, res: Response) => {
	try {
		const { token } = req.query;
		if (!token || typeof token !== "string") {
			return res.status(400).json({ message: "Token required" });
		}

		const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
		if (payload.type !== "magic" || !payload.email) {
			return res.status(401).json({ message: "Invalid magic link" });
		}

		const account = await AccountModel.findOne({ email: payload.email });
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		// Generate new tokens
		const { accessToken, refreshToken } = generateTokens(
			account._id.toString()
		);

		// Store refresh token
		const refreshTokenHash = crypto
			.createHash("sha256")
			.update(refreshToken)
			.digest("hex");
		account.refreshTokens = account.refreshTokens || [];
		account.refreshTokens.push(refreshTokenHash);
		await account.save();

		res.json({
			message: "Magic link verified",
			accessToken,
			refreshToken,
			user: {
				id: account._id,
				email: account.email,
				role: account.role,
				username: account.username,
			},
		});
	} catch (error) {
		console.error("Magic link verification error:", error);
		res.status(401).json({ message: "Invalid magic link" });
	}
};

