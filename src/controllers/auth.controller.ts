import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { AuthRequest } from "../middlewares/auth.middleware";
import { AccountModel } from "../models/users/account.model";
import { ReaderProfileModel } from "../models/users/reader-profile.model";
import { sendMail } from "../lib/mailer";

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
	action: "login" | "signup";
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

const generateMagicLink = (email: string, action: "login" | "signup") => {
	const token = jwt.sign(
		{ email, type: "magic", action } as TokenPayload,
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
		let account = await AccountModel.findOne({ email });

		let action: "login" | "signup" = "login";

		if (!account) {
			// auto-create account for signup
			account = new AccountModel({ email });
			await account.save();
			action = "signup";
		}

		const magicLink = generateMagicLink(email, action);
		const subject =
			action === "signup"
				? "Welcome to HealthScope! Confirm your signup"
				: "HealthScope Magic Login Link";

		try {
			await sendMail({
				to: email,
				subject,
				text: `Here is your healthscope magic link, it expires in 10 minutes:\n${magicLink}`,
				html: `<p>Click below to continue:</p><p><a href="${magicLink}">${magicLink}</a></p>`,
			});

			res.json({
				success: true,
				msg: `Magic link sent for ${action}`,
			});
		} catch (error) {
			console.error("Email error:", error);
			res.status(500).json({ success: false, msg: "Failed to send email" });
		}
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

/**
 * Use after user signs up with magic link where there was no inital password set up
 */
export const setPassword = async (req: AuthRequest, res: Response) => {
	try {
		const { password } = req.body;

		// Validation
		if (!password || password.length < 8) {
			return res.status(400).json({
				message: "Password must be at least 8 characters long",
			});
		}

		// Ensure user is attached by middleware
		const account = req.user;
		if (!account) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		// Hash password
		const salt = await bcrypt.genSalt(10);
		account.password = await bcrypt.hash(password, salt);

		await account.save();

		return res.json({
			success: true,
			message: "Password set successfully",
		});
	} catch (error) {
		console.error("Set password error:", error);
		return res.status(500).json({ message: "Error setting password" });
	}
};