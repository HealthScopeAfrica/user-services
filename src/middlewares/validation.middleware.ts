import { Request, Response, NextFunction } from "express";
import { Schema } from "joi";

export const validateRequest = (schema: Schema) => {
	return (req: Request, res: Response, next: NextFunction) => {
		const { error } = schema.validate(req.body, { abortEarly: false });

		console.log(error);

		if (error) {
			const errorMessage = error.details
				.map((detail) => detail.message)
				.join(", ");
			return res.status(400).json({
				message: "Validation error",
				errors: errorMessage,
			});
		}

		next();
	};
};
