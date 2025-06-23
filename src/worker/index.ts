import dotenv from 'dotenv';
import path from 'path';

// Load environment variables FIRST before any other imports
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

// Now import everything else
import logger from '@config/logger.config';
import { startWorkers, stopWorkers, getWorkersStatus } from '@services/queue/worker.service';
import { initializeQueueService } from '@services/queue/queue.service';

// Graceful shutdown flag
let isShuttingDown = false;

/**
 * Start the worker process
 */
async function start(): Promise<void> {
    try {
        logger.info('Starting worker process...');

        // Initialize queue service first
        await initializeQueueService();
        logger.info('Queue service initialized');

        // Start all workers
        await startWorkers();
        logger.info('Worker process started successfully');

        // Log worker status
        const status = await getWorkersStatus();
        logger.info('Worker status:', status);

        // Keep the process alive
        process.stdin.resume();
    } catch (error) {
        logger.error('Failed to start worker process', error);
        process.exit(1);
    }
}

/**
 * Graceful shutdown
 */
async function shutdown(): Promise<void> {
    if (isShuttingDown) {
        logger.info('Shutdown already in progress...');
        return;
    }

    isShuttingDown = true;
    logger.info('Shutting down worker process...');

    try {
        // Stop all workers
        await stopWorkers();
        logger.info('All workers stopped');

        // Give some time for cleanup
        await new Promise((resolve) => setTimeout(resolve, 1000));

        logger.info('Worker process shut down successfully');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown', error);
        process.exit(1);
    }
}

/**
 * Health check for monitoring
 */
async function healthCheck(): Promise<void> {
    try {
        const status = await getWorkersStatus();
        logger.info('Health check - Worker status:', status);
    } catch (error) {
        logger.error('Health check failed', error);
    }
}

// Handle process signals for graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM signal');
    await shutdown();
});

process.on('SIGINT', async () => {
    logger.info('Received SIGINT signal');
    await shutdown();
});

// Handle unexpected errors
process.on('uncaughtException', (error) => {
    logger.error('Uncaught exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Log worker configuration on startup
logger.info('Worker configuration:', {
    NODE_ENV: process.env.NODE_ENV,
    REDIS_HOST: process.env.REDIS_HOST || 'localhost',
    REDIS_PORT: process.env.REDIS_PORT || 6379,
    QUEUE_CONCURRENCY: process.env.QUEUE_CONCURRENCY || 5,
    QUEUE_RETRY_ATTEMPTS: process.env.QUEUE_RETRY_ATTEMPTS || 3
});

// Optional: Set up periodic health checks
if (process.env.WORKER_HEALTH_CHECK_INTERVAL) {
    const interval = Number(process.env.WORKER_HEALTH_CHECK_INTERVAL) * 1000;
    setInterval(healthCheck, interval);
    logger.info(`Health check interval set to ${interval}ms`);
}

// Start the worker process
start().catch((error) => {
    logger.error('Fatal error starting worker process', error);
    process.exit(1);
});
