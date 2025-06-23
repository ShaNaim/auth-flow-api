import { Queue, QueueOptions, JobsOptions } from 'bullmq';
import { createRedisConnection } from '@config/redis.config';
import logger from '@config/logger.config';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
import {
    AccountBlockedEmailData,
    EmailJobData,
    EmailJobName,
    PasswordResetEmailData,
    QueueName,
    VerificationEmailData,
    WelcomeEmailData
} from './queue.types';

class QueueService {
    private queues: Map<QueueName, Queue> = new Map();
    private connection: any;
    private isInitialized: boolean = false;

    async initialize(): Promise<void> {
        if (this.isInitialized) {
            logger.warn('Queue service already initialized');
            return;
        }

        try {
            logger.info('Initializing queue service...');

            this.connection = createRedisConnection();

            await this.initializeQueues();

            this.isInitialized = true;
            logger.info('Queue service initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize queue service', error);
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Failed to initialize queue service',
                data: {
                    path: ['queue', 'service', 'initialize'],
                    message: error instanceof Error ? error.message : 'Unknown error'
                },
                isOperational: false
            });
        }
    }

    // eslint-disable-next-line @typescript-eslint/require-await, require-await
    private async initializeQueues(): Promise<void> {
        const queueOptions: QueueOptions = {
            connection: this.connection,
            defaultJobOptions: {
                attempts: Number(process.env.QUEUE_RETRY_ATTEMPTS) || 3,
                backoff: {
                    type: 'exponential',
                    delay: 2000
                },
                removeOnComplete: {
                    age: 3600,
                    count: 100
                },
                removeOnFail: {
                    age: 24 * 3600
                }
            }
        };

        const emailQueue = new Queue(QueueName.EMAIL, queueOptions);
        this.queues.set(QueueName.EMAIL, emailQueue);
        logger.info(`Queue "${QueueName.EMAIL}" created`);

        const userCleanupQueue = new Queue(QueueName.USER_CLEANUP, queueOptions);
        this.queues.set(QueueName.USER_CLEANUP, userCleanupQueue);
        logger.info(`Queue "${QueueName.USER_CLEANUP}" created`);

        const reportQueue = new Queue(QueueName.REPORT_GENERATION, queueOptions);
        this.queues.set(QueueName.REPORT_GENERATION, reportQueue);
        logger.info(`Queue "${QueueName.REPORT_GENERATION}" created`);
    }

    getQueue(name: QueueName): Queue {
        if (!this.isInitialized) {
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Queue service not initialized',
                data: {
                    path: ['queue', 'service', 'getQueue'],
                    message: 'Call initialize() before using queue service'
                }
            });
        }

        const queue = this.queues.get(name);
        if (!queue) {
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: 'Queue not found',
                data: {
                    path: ['queue', 'service', 'getQueue'],
                    message: `Queue "${name}" does not exist`
                }
            });
        }

        return queue;
    }

    async addEmailJob(jobData: EmailJobData, options?: JobsOptions): Promise<string> {
        try {
            const emailQueue = this.getQueue(QueueName.EMAIL);

            const dataWithTimestamp = {
                ...jobData.data,
                timestamp: jobData.data.timestamp || Date.now()
            };

            const job = await emailQueue.add(jobData.name, dataWithTimestamp, {
                ...options,
                attempts: options?.attempts || 3,
                backoff: options?.backoff || {
                    type: 'exponential',
                    delay: 2000
                }
            });

            logger.info(`Email job added: ${jobData.name}`, {
                jobId: job.id,
                email: jobData.data.email,
                userId: jobData.data.userId
            });

            return job.id || 'unknown';
        } catch (error) {
            logger.error('Failed to add email job', error);
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Failed to add email job',
                data: {
                    path: ['queue', 'service', 'addEmailJob'],
                    message: error instanceof Error ? error.message : 'Unknown error'
                }
            });
        }
    }

    async addUserCleanupJob(userId: number, options?: JobsOptions): Promise<string> {
        try {
            const cleanupQueue = this.getQueue(QueueName.USER_CLEANUP);

            const job = await cleanupQueue.add(
                'cleanup-inactive-user',
                {
                    userId,
                    timestamp: Date.now()
                },
                {
                    ...options,
                    delay: options?.delay || 30 * 24 * 60 * 60 * 1000
                }
            );

            logger.info(`User cleanup job added for user: ${userId}`, {
                jobId: job.id,
                delay: options?.delay
            });

            return job.id || 'unknown';
        } catch (error) {
            logger.error('Failed to add user cleanup job', error);
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Failed to add user cleanup job',
                data: {
                    path: ['queue', 'service', 'addUserCleanupJob'],
                    message: error instanceof Error ? error.message : 'Unknown error'
                }
            });
        }
    }

    async getQueueMetrics(queueName: QueueName) {
        try {
            const queue = this.getQueue(queueName);

            const [waiting, active, completed, failed, delayed] = await Promise.all([
                queue.getWaitingCount(),
                queue.getActiveCount(),
                queue.getCompletedCount(),
                queue.getFailedCount(),
                queue.getDelayedCount()
            ]);

            return {
                name: queueName,
                counts: {
                    waiting,
                    active,
                    completed,
                    failed,
                    delayed
                }
            };
        } catch (error) {
            logger.error(`Failed to get metrics for queue: ${queueName}`, error);
            throw error;
        }
    }

    async pauseQueue(queueName: QueueName): Promise<void> {
        const queue = this.getQueue(queueName);
        await queue.pause();
        logger.info(`Queue "${queueName}" paused`);
    }

    async resumeQueue(queueName: QueueName): Promise<void> {
        const queue = this.getQueue(queueName);
        await queue.resume();
        logger.info(`Queue "${queueName}" resumed`);
    }

    async shutdown(): Promise<void> {
        logger.info('Shutting down queue service...');

        try {
            for (const [name, queue] of this.queues) {
                await queue.close();
                logger.info(`Queue "${name}" closed`);
            }

            this.queues.clear();

            if (this.connection) {
                await this.connection.quit();
            }

            this.isInitialized = false;
            logger.info('Queue service shut down successfully');
        } catch (error) {
            logger.error('Error during queue service shutdown', error);
            throw error;
        }
    }
}

export const queueService = new QueueService();

export async function initializeQueueService(): Promise<void> {
    await queueService.initialize();
}

export async function addWelcomeEmail(data: WelcomeEmailData): Promise<string> {
    return await queueService.addEmailJob({
        name: EmailJobName.WELCOME,
        data
    });
}

export async function addPasswordResetEmail(data: PasswordResetEmailData): Promise<string> {
    return await queueService.addEmailJob({
        name: EmailJobName.PASSWORD_RESET,
        data
    });
}

export async function addVerificationEmail(data: VerificationEmailData): Promise<string> {
    return await queueService.addEmailJob({
        name: EmailJobName.VERIFICATION,
        data
    });
}

export async function addAccountBlockedEmail(data: AccountBlockedEmailData): Promise<string> {
    return await queueService.addEmailJob({
        name: EmailJobName.ACCOUNT_BLOCKED,
        data
    });
}

export {
    AccountBlockedEmailData,
    EmailJobData,
    EmailJobName,
    PasswordResetEmailData,
    QueueName,
    VerificationEmailData,
    WelcomeEmailData
} from './queue.types';
