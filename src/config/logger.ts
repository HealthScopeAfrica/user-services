import winston from "winston";
import morgan from "morgan";

// Winston logger configuration with modern object spread and async/await support
const createLogger = (): winston.Logger =>
	winston.createLogger({
		level: "info",
		format: winston.format.combine(
			winston.format.colorize(),
			winston.format.timestamp(),
			winston.format.printf(
				({
					timestamp,
					level,
					message,
				}: winston.Logform.TransformableInfo): string =>
					`[${timestamp}] ${level}: ${message}`
			)
		),
		transports: [new winston.transports.Console()],
	});

// Create logger instance
export const logger: winston.Logger = createLogger();

// Morgan stream configuration with arrow function and modern syntax
export const morganStream: morgan.StreamOptions = {
	write: (message: string): void => {
		logger.info(message.trim());
	},
};

export const morganMiddleware = morgan("combined", { stream: morganStream });

export default logger;
