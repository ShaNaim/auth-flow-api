import winston from 'winston';
import expressWinston from 'express-winston';
import { v4 as uuidv4 } from 'uuid';
import { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import environment from '@config/config';

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

// Define log file paths
const logFilePath = path.join(logsDir, `app-${new Date().toISOString().split('T')[0]}.log`);
const errorLogFilePath = path.join(logsDir, `error-${new Date().toISOString().split('T')[0]}.log`);

// Custom log format with colors for console
const consoleFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.colorize({ all: true }),
    winston.format.printf(({ level, message, timestamp, requestId }) => {
        const reqIdStr = requestId ? `[${requestId}] ` : '';
        // const metaStr = Object.keys(metadata).length ? `\n${JSON.stringify(metadata, null, 2)}` : '';
        return `${timestamp} ${level}: ${reqIdStr}${message}`;
    })
);

// Log format for file (without colors)
const fileFormat = winston.format.combine(winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }), winston.format.json());

// Create Winston logger
const logger = winston.createLogger({
    level: environment?.log_level || 'info',
    defaultMeta: false,
    transports: [
        // Console transport
        new winston.transports.Console({
            format: consoleFormat
        }),
        // All logs file transport
        new winston.transports.File({
            filename: logFilePath,
            format: fileFormat
        }),
        // Error logs file transport
        new winston.transports.File({
            filename: errorLogFilePath,
            level: 'error',
            format: fileFormat
        })
    ],
    // Don't exit on error
    exitOnError: false
});

// Function to clean sensitive data
const sanitizeData = (data: any): any => {
    if (!data) return data;

    const sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'creditCard'];
    if (typeof data !== 'object') return data;

    const sanitized = { ...data };
    for (const field of sensitiveFields) {
        if (field in sanitized) {
            sanitized[field] = '[REDACTED]';
        }
    }

    return sanitized;
};

// Extend Express Request type to include logger and id
declare module 'express-serve-static-core' {
    interface Request {
        logger: winston.Logger;
        id: string;
    }

    interface Response {
        body?: any;
    }
}

// Create request ID middleware
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // Use existing request ID or generate a new one
    req.id = (req.headers['x-request-id'] as string) || uuidv4();

    // Add request ID to response headers
    res.setHeader('x-request-id', req.id);

    // Create a child logger with request ID
    req.logger = logger.child({ requestId: req.id });

    next();
};

// Request logger middleware
const requestLogger = expressWinston.logger({
    winstonInstance: logger,
    statusLevels: true, // Maps HTTP status to log levels
    // Log request details
    requestWhitelist: ['method', 'url', 'headers', 'query', 'body'],
    // Limit response logging to avoid massive logs
    responseWhitelist: ['statusCode', 'body'],
    // Don't log for common static resources
    ignoredRoutes: ['/health', '/favicon.ico', '/static'],
    // Custom message format
    msg: 'HTTP {{req.method}} {{req.url}} {{res.statusCode}} {{res.responseTime}}ms',
    // Custom request/response sanitizer
    requestFilter: (req, propName) => {
        if (propName === 'body') {
            return sanitizeData(req.body);
        }
        return req[propName];
    },
    responseFilter: (res, propName) => {
        if (propName === 'body') {
            return sanitizeData(res.body);
        }
        return res[propName];
    },
    // Add request ID to log context
    dynamicMeta: (req) => {
        return {
            requestId: req.id
        };
    }
});

const errorLogger = expressWinston.errorLogger({
    winstonInstance: logger,
    // Fix: Use the correct property name for including stack traces
    meta: true, // This enables metadata which includes stack traces
    // You can also explicitly include the stack trace in your format:
    metaField: 'error',
    // Custom message format
    msg: 'Error processing {{req.method}} {{req.url}}',
    // Add request ID to log context
    dynamicMeta: (req) => {
        return {
            requestId: req.id
        };
    }
});

// Create a custom response logger to capture responses
const responseLogger = (_: Request, res: Response, next: NextFunction) => {
    const originalSend = res.send;

    res.send = function (body?: any): Response {
        // Now res.body is properly typed through interface extension
        res.body = body;
        return originalSend.apply(this, arguments as any);
    };

    next();
};

// Export main logger and utility functions
export default logger;
export { requestLogger, errorLogger, responseLogger };
