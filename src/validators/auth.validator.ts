import Joi from "joi";

export const registerSchema = Joi.object({
	email: Joi.string().email().required().lowercase().trim(),
	password: Joi.string().min(6).required(),
	role: Joi.string().valid("reader").optional().default("reader"),
	username: Joi.string().min(3).optional(),
	firstName: Joi.string().trim().optional(),
	lastName: Joi.string().trim().optional(),
});

export const loginSchema = Joi.object({
	email: Joi.string().email().required().lowercase().trim(),
	password: Joi.string().required(),
});
