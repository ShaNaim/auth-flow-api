import { Worker, Job, WorkerOptions } from 'bullmq';
import { createRedisConnection } from '@config/redis.config';
import logger from '@config/logger.config';
import { emailService } from '@services/email/email.service';
import {
    QueueName,
    EmailJobName,
    WelcomeEmailData,
    PasswordResetEmailData,
    VerificationEmailData,
    AccountBlockedEmailData
} from '@services/queue/queue.service';

// Worker class for processing email jobs
class EmailWorker {
    private worker: Worker | null = null;
    private isRunning: boolean = false;

    // eslint-disable-next-line require-await, @typescript-eslint/require-await
    async start(): Promise<void> {
        if (this.isRunning) {
            logger.warn('Email worker is already running');
            return;
        }

        try {
            logger.info('Starting email worker...');

            const connection = createRedisConnection();

            const workerOptions: WorkerOptions = {
                connection,
                concurrency: Number(process.env.QUEUE_CONCURRENCY) || 5,
                removeOnComplete: { count: 100 },
                removeOnFail: { count: 100 }
            };

            this.worker = new Worker(
                QueueName.EMAIL,
                async (job: Job) => {
                    return await this.processEmailJob(job);
                },
                workerOptions
            );

            // Set up event listeners
            this.setupEventListeners();

            this.isRunning = true;
            logger.info('Email worker started successfully');
        } catch (error) {
            logger.error('Failed to start email worker', error);
            throw error;
        }
    }

    private async processEmailJob(job: Job): Promise<any> {
        logger.info(`Processing email job: ${job.name}`, { jobId: job.id });

        try {
            switch (job.name) {
                case EmailJobName.WELCOME:
                    return await this.processWelcomeEmail(job.data as WelcomeEmailData);

                case EmailJobName.PASSWORD_RESET:
                    return await this.processPasswordResetEmail(job.data as PasswordResetEmailData);

                case EmailJobName.VERIFICATION:
                    return await this.processVerificationEmail(job.data as VerificationEmailData);

                case EmailJobName.ACCOUNT_BLOCKED:
                    return await this.processAccountBlockedEmail(job.data as AccountBlockedEmailData);

                default:
                    throw new Error(`Unknown email job type: ${job.name}`);
            }
        } catch (error) {
            logger.error(`Failed to process email job: ${job.name}`, {
                jobId: job.id,
                error: error instanceof Error ? error.message : 'Unknown error',
                data: job.data
            });
            throw error;
        }
    }

    private async processWelcomeEmail(data: WelcomeEmailData): Promise<any> {
        const messageId = await emailService.sendWelcomeEmail(data.email, {
            firstName: data.firstName,
            verificationToken: data.verificationToken
        });

        return {
            success: true,
            messageId,
            email: data.email,
            type: EmailJobName.WELCOME
        };
    }

    private async processPasswordResetEmail(data: PasswordResetEmailData): Promise<any> {
        const messageId = await emailService.sendPasswordResetEmail(data.email, {
            firstName: data.firstName,
            resetToken: data.resetToken
        });

        return {
            success: true,
            messageId,
            email: data.email,
            type: EmailJobName.PASSWORD_RESET
        };
    }

    private async processVerificationEmail(data: VerificationEmailData): Promise<any> {
        const messageId = await emailService.sendVerificationEmail(data.email, {
            firstName: data.firstName,
            verificationToken: data.verificationToken
        });

        return {
            success: true,
            messageId,
            email: data.email,
            type: EmailJobName.VERIFICATION
        };
    }

    private async processAccountBlockedEmail(data: AccountBlockedEmailData): Promise<any> {
        const messageId = await emailService.sendAccountBlockedEmail(data.email, {
            firstName: data.firstName,
            reason: data.reason
        });

        return {
            success: true,
            messageId,
            email: data.email,
            type: EmailJobName.ACCOUNT_BLOCKED
        };
    }

    private setupEventListeners(): void {
        if (!this.worker) return;

        this.worker.on('completed', (job) => {
            logger.info(`Job completed: ${job.name}`, {
                jobId: job.id,
                returnValue: job.returnvalue
            });
        });

        this.worker.on('failed', (job, err) => {
            logger.error(`Job failed: ${job?.name}`, {
                jobId: job?.id,
                error: err.message,
                attemptsMade: job?.attemptsMade
            });
        });

        this.worker.on('active', (job) => {
            logger.info(`Job started: ${job.name}`, {
                jobId: job.id,
                attempt: job.attemptsMade + 1
            });
        });

        this.worker.on('error', (err) => {
            logger.error('Worker error:', err);
        });

        this.worker.on('stalled', (jobId) => {
            logger.warn(`Job stalled: ${jobId}`);
        });
    }

    async stop(): Promise<void> {
        if (!this.isRunning || !this.worker) {
            logger.warn('Email worker is not running');
            return;
        }

        try {
            logger.info('Stopping email worker...');
            await this.worker.close();
            this.worker = null;
            this.isRunning = false;
            logger.info('Email worker stopped successfully');
        } catch (error) {
            logger.error('Failed to stop email worker', error);
            throw error;
        }
    }

    isWorkerRunning(): boolean {
        return this.isRunning;
    }

    // eslint-disable-next-line require-await, @typescript-eslint/require-await
    async getStatus(): Promise<any> {
        if (!this.worker) {
            return { running: false };
        }

        return {
            running: this.isRunning,
            isPaused: this.worker.isPaused(),
            isRunning: this.worker.isRunning()
        };
    }
}

// Worker class for user cleanup jobs
class UserCleanupWorker {
    private worker: Worker | null = null;
    private isRunning: boolean = false;
    // eslint-disable-next-line require-await, @typescript-eslint/require-await
    async start(): Promise<void> {
        if (this.isRunning) {
            logger.warn('User cleanup worker is already running');
            return;
        }

        try {
            logger.info('Starting user cleanup worker...');

            const connection = createRedisConnection();

            const workerOptions: WorkerOptions = {
                connection,
                concurrency: 1, // Process one cleanup at a time
                removeOnComplete: { count: 50 },
                removeOnFail: { count: 50 }
            };

            this.worker = new Worker(
                QueueName.USER_CLEANUP,
                async (job: Job) => {
                    return await this.processCleanupJob(job);
                },
                workerOptions
            );

            this.isRunning = true;
            logger.info('User cleanup worker started successfully');
        } catch (error) {
            logger.error('Failed to start user cleanup worker', error);
            throw error;
        }
    }
    // eslint-disable-next-line require-await, @typescript-eslint/require-await
    private async processCleanupJob(job: Job): Promise<any> {
        const { userId } = job.data;
        logger.info(`Processing user cleanup for user: ${userId}`, { jobId: job.id });

        // TODO: Implement actual cleanup logic
        // For now, just log and return
        logger.info(`User cleanup completed for user: ${userId}`);

        return {
            success: true,
            userId,
            cleanedAt: new Date().toISOString()
        };
    }

    async stop(): Promise<void> {
        if (!this.isRunning || !this.worker) {
            logger.warn('User cleanup worker is not running');
            return;
        }

        try {
            logger.info('Stopping user cleanup worker...');
            await this.worker.close();
            this.worker = null;
            this.isRunning = false;
            logger.info('User cleanup worker stopped successfully');
        } catch (error) {
            logger.error('Failed to stop user cleanup worker', error);
            throw error;
        }
    }

    isWorkerRunning(): boolean {
        return this.isRunning;
    }
}

// Worker manager to handle all workers
class WorkerManager {
    private emailWorker: EmailWorker;
    private userCleanupWorker: UserCleanupWorker;

    constructor() {
        this.emailWorker = new EmailWorker();
        this.userCleanupWorker = new UserCleanupWorker();
    }

    async startAll(): Promise<void> {
        logger.info('Starting all workers...');

        // Initialize email service first
        await emailService.initialize();

        // Start workers
        await Promise.all([this.emailWorker.start(), this.userCleanupWorker.start()]);

        logger.info('All workers started successfully');
    }

    async stopAll(): Promise<void> {
        logger.info('Stopping all workers...');

        await Promise.all([this.emailWorker.stop(), this.userCleanupWorker.stop()]);

        // Close email service
        await emailService.close();

        logger.info('All workers stopped successfully');
    }

    async getStatus(): Promise<any> {
        return {
            email: await this.emailWorker.getStatus(),
            userCleanup: {
                running: this.userCleanupWorker.isWorkerRunning()
            }
        };
    }
}

// Export singleton instance
export const workerManager = new WorkerManager();

// Export convenience functions
export async function startWorkers(): Promise<void> {
    await workerManager.startAll();
}

export async function stopWorkers(): Promise<void> {
    await workerManager.stopAll();
}

export async function getWorkersStatus(): Promise<any> {
    return await workerManager.getStatus();
}
