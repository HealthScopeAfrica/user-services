import { Request, Response, Router } from "express";
import {
	deleteProfile,
	getProfile,
	updateProfile,
	updateProfilePicture,
} from "../controllers/user.controller";
import { authenticate, AuthRequest } from "../middlewares/auth.middleware";
import { upload } from "../middlewares/upload.middleware";

const router = Router();

router.get("/", (_req: Request, res: Response) => {
	res.send("HealthScope User Resources");
});

router.get("/profile", authenticate, getProfile);

// Profile management
router.put(
	"/profile",
	authenticate,
	upload.single("profilePicture"),
	updateProfile
);
router.put(
	"/profile/picture",
	authenticate,
	upload.single("profilePicture"),
	updateProfilePicture
);
router.delete("/profile", authenticate, deleteProfile);

export default router;
