import logger from "../config/logger";
import { Request, Response, NextFunction } from "express";


interface CustomError extends Error {
    status?: number;
}

const errorHandler = (
    err: CustomError,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    // Log only the error message and status for cleaner output
    logger.error(`${err.status || 500} - ${err.message}`);
    res.status(err.status || 500).json({
        success: false,
        statusCode: err.status || 500,
        message: err.message || 'Internal Server Error'
    });
};

export default errorHandler;