// Add to your main app.ts or articles.route.ts
import rateLimit from "express-rate-limit";

const rateLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // limit each IP to 100 requests per window
	message: "Too many requests, please try again later.",
});

export default rateLimiter;