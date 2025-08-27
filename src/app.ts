import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import path from "path";
import cookieParser from "cookie-parser";
import logger from "morgan";
import createError, { HttpError } from "http-errors";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import errorHandler from "./middlewares/errorHandler";
import connectDB from './config/db';

import indexRouter from "./routes/index";
import usersRouter from "./routes/users";
import authRouter from "./routes/auth";

const app = express();

const initDatabase = async () => {
	await connectDB();
};

initDatabase();

// View engine setup
app.set("views", path.join(__dirname, "..", "views"));
app.set("view engine", "ejs");

// Middlewares
app.use(helmet());
app.use(cors());
app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(compression());
app.use(express.static(path.join(__dirname, "..", "public")));

// Routes
app.use("/api/v1", indexRouter);
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/user", usersRouter);

// 404 handler
app.use((_req, _res, next) => {
	next(createError(404));
});

app.use(errorHandler);

// // Error handler
// app.use((err: HttpError, req: Request, res: Response, _next: NextFunction) => {
// 	// Set locals, only providing errors in development
// 	res.locals.message = err.message;
// 	res.locals.error = req.app.get("env") === "development" ? err : {};

// 	res.status(err.status || 500);
// 	const accept = req.headers["accept"] ?? "";
// 	if (accept.includes("application/json")) {
// 		res.json({ error: res.locals.message, status: err.status || 500 });
// 	} else {
// 		res.render("error", {
// 			message: res.locals.message,
// 			error: res.locals.error,
// 		});
// 	}
// });



export default app;
