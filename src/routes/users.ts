import { Request, Response, Router } from "express";
import {
	deleteProfile,
	updateProfile,
	updateProfilePicture,
} from "../controllers/auth.controller";
import { authenticate, AuthRequest } from "../middlewares/auth.middleware";
import { upload } from "../middlewares/upload.middleware";

const router = Router();

/* GET users listing. */
router.get("/", (_req: Request, res: Response) => {
	res.send("HealthScope User Resources");
});

router.get("/me", authenticate, (req: AuthRequest, res) => {
	res.json({ user: req.user });
});

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
