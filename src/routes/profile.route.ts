import { Request, Response, Router } from "express";
import {
	deleteProfile,
	getProfile,
	updateProfile,
	updateProfilePicture,
} from "../controllers/profile.controller";
import { authenticate, AuthRequest } from "../middlewares/auth.middleware";
import { upload } from "../middlewares/upload.middleware";

const router = Router();

router.get("/", (_req: Request, res: Response) => {
	res.send("HealthScope User Resources");
});

router.get("/me", authenticate, getProfile);

// Profile management
router.put(
	"/",
	authenticate,
	upload.single("profilePicture"),
	updateProfile
);
router.put(
	"/picture",
	authenticate,
	upload.single("profilePicture"),
	updateProfilePicture
);
router.delete("/", authenticate, deleteProfile);

export default router;
