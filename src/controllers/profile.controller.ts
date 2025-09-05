import { Response } from "express";
import { AuthRequest } from "../middlewares/auth.middleware";
import { AccountModel } from "../models/users/account.model";
import { ReaderProfileModel } from "../models/users/reader-profile.model";

export const getProfile = async (req: AuthRequest, res: Response) => {
	try {
		const userId = req.user?._id;

		const account = await AccountModel.findById(userId).select(
			"-passwordHash -__v"
		);
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		const profile = await ReaderProfileModel.findOne({
			accountId: userId,
		}).select("-__v");
		if (!profile) {
			return res.status(404).json({ message: "Profile not found" });
		}

		// Convert mongoose docs to plain JS objects
		const accountObj = account.toObject();
		const profileObj = profile.toObject();

		// Merge while keeping only the useful fields
		const merged = {
			email: accountObj.email,
			username: accountObj.username,
			role: accountObj.role,
			status: accountObj.status,
			profilePicture: profileObj.profilePicture,
			profileCompleted: accountObj.profileCompleted,
			createdAt: accountObj.createdAt,
			lastLoginAt: accountObj.lastLoginAt,
			firstName: profileObj.firstName,
			lastName: profileObj.lastName,
			allergies: profileObj.allergies,
			conditions: profileObj.conditions,
			medications: profileObj.medications,
			emergencyContacts: profileObj.emergencyContacts,
		};

		res.json(merged);
	} catch (error) {
		console.error("Profile retrieval error:", error);
		res.status(500).json({ message: "Error retrieving profile" });
	}
};

export const updateProfile = async (req: AuthRequest, res: Response) => {
	try {
		const userId = req.user?._id;

		const { firstName, lastName, ...otherDetails } = req.body;
		const profilePicture = req.file?.path; // Assuming you're using multer for file uploads

		const account = await AccountModel.findById(userId);
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		const profile = await ReaderProfileModel.findOneAndUpdate(
			{ accountId: userId },
			{
				firstName,
				lastName,
				...(profilePicture && { profilePicture }),
				...otherDetails,
			},
			{ new: true }
		);

		res.json({ message: "Profile updated successfully", profile });
	} catch (error) {
		console.error("Profile update error:", error);
		res.status(500).json({ message: "Error updating profile" });
	}
};

export const updateProfilePicture = async (req: AuthRequest, res: Response) => {
	try {
		const userId = req.user?._id;
		const profilePicture = req.file?.path;

		if (!profilePicture) {
			return res.status(400).json({ message: "Profile picture required" });
		}

		const account = await AccountModel.findById(userId);
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		const profile = await ReaderProfileModel.findOneAndUpdate(
			{ accountId: userId },
			{ profilePicture },
			{ new: true }
		);

		res.json({
			message: "Profile picture updated successfully",
			profilePicture: profile.profilePicture,
		});
	} catch (error) {
		console.error("Profile picture update error:", error);
		res.status(500).json({ message: "Error updating profile picture" });
	}
};

export const deleteProfile = async (req: AuthRequest, res: Response) => {
	try {
		const userId = req.user?._id;

		const account = await AccountModel.findById(userId);
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		await ReaderProfileModel.deleteOne({ accountId: userId });

		// Delete account unless you want to be naughty and keep user data 😏
		await AccountModel.deleteOne({ _id: userId });

		res.json({ message: "Profile deleted successfully" });
	} catch (error) {
		console.error("Profile deletion error:", error);
		res.status(500).json({ message: "Error deleting profile" });
	}
};
