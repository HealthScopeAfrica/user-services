// Install: npm install express-validator
import { query, param } from "express-validator";

const validateSearch = [
	query("q")
		.trim()
		.isLength({ min: 2, max: 100 })
		.withMessage("Search query must be 2-100 characters"),
	query("page")
		.optional()
		.isInt({ min: 1 })
		.withMessage("Page must be a positive integer"),
];

export { validateSearch };