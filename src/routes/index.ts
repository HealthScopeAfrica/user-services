import { Router, Request, Response } from "express";

const router = Router();

/* GET users listing. */
router.get("/", (_req: Request, res: Response) => {
	res.send("Healthscope User Resources");
});

export default router;
