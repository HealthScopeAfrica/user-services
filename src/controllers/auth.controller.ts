import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { AccountModel } from "../models/users/account.model";
import { ReaderProfileModel } from "../models/users/reader-profile.model";

const JWT_SECRET = process.env.JWT_SECRET || "secret-key"; // TODO: Move to config

export const register = async (req: Request, res: Response) => {
	try {
		const { email, password, role, username, firstName, lastName } = req.body;

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
			role,
			username,
			status: "enabled",
		});

		// Create role-specific profile
		switch (role) {
			case "reader":
				await ReaderProfileModel.create({
					accountId: account._id,
					firstName,
					lastName,
				});
				break;
			// Add cases for other roles in the same format
			// case 'partner':
			//   await PartnerProfileModel.create({ accountId: account._id, ...otherStuff });
			//   break;
		}

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
			return res.status(403).json({ message: "Account is disabled" });
		}

		// Update last login
		account.lastLoginAt = new Date();
		await account.save();

		// Generate JWT
		const token = jwt.sign({ userId: account._id }, JWT_SECRET, {
			expiresIn: "24h",
		});

		res.json({
			message: "Login successful",
			token,
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
