import { Response } from "express";
import { AuthRequest } from "../middlewares/auth.middleware";
import { AccountModel } from "../models/users/account.model";
import { ReaderProfileModel } from "../models/users/reader-profile.model";



export const updateProfile = async (req: AuthRequest, res: Response) => {
	try {
		const userId = req.user?.userId;
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
		const userId = req.user?.userId;
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

		res.json({ message: "Profile picture updated successfully", profile });
	} catch (error) {
		console.error("Profile picture update error:", error);
		res.status(500).json({ message: "Error updating profile picture" });
	}
};

export const deleteProfile = async (req: AuthRequest, res: Response) => {
	try {
		const userId = req.user?.userId;

		const account = await AccountModel.findById(userId);
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		await ReaderProfileModel.deleteOne({ accountId: userId });

		// Delete account
		await AccountModel.deleteOne({ _id: userId });

		res.json({ message: "Profile deleted successfully" });
	} catch (error) {
		console.error("Profile deletion error:", error);
		res.status(500).json({ message: "Error deleting profile" });
	}
};
