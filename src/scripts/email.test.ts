import dotenv from 'dotenv';
import path from 'path';
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

import { emailService } from '@services/email/email.service';
import logger from '@config/logger.config';

async function testEmailService() {
    try {
        logger.info('Starting email service test...');

        await emailService.initialize();
        logger.info('Email service initialized');

        const testEmail = process.argv[2] || process.env.TEST_EMAIL;

        if (!testEmail) {
            logger.error('Please provide a test email address');
            logger.info('Usage: npm run test:email your-email@example.com');
            process.exit(1);
        }

        logger.info(`Sending test emails to: ${testEmail}`);

        logger.info('Sending welcome email...');
        const welcomeResult = await emailService.sendWelcomeEmail(testEmail, {
            firstName: 'Test User'
        });
        logger.info(`Welcome email sent successfully. Message ID: ${welcomeResult}`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
        logger.info('Sending welcome email with verification...');
        const welcomeWithVerifyResult = await emailService.sendWelcomeEmail(testEmail, {
            firstName: 'Test User',
            verificationToken: 'test-verification-token-123'
        });
        logger.info(`Welcome email with verification sent successfully. Message ID: ${welcomeWithVerifyResult}`);
        await new Promise((resolve) => setTimeout(resolve, 2000));

        logger.info('Sending password reset email...');
        const resetResult = await emailService.sendPasswordResetEmail(testEmail, {
            firstName: 'Test User',
            resetToken: 'test-reset-token-456'
        });
        logger.info(`Password reset email sent successfully. Message ID: ${resetResult}`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
        logger.info('Sending verification email...');
        const verifyResult = await emailService.sendVerificationEmail(testEmail, {
            firstName: 'Test User',
            verificationToken: 'test-verify-token-789'
        });
        logger.info(`Verification email sent successfully. Message ID: ${verifyResult}`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
        logger.info('Sending account blocked email...');
        const blockedResult = await emailService.sendAccountBlockedEmail(testEmail, {
            firstName: 'Test User',
            reason: 'testing purposes only'
        });
        logger.info(`Account blocked email sent successfully. Message ID: ${blockedResult}`);

        logger.info('All test emails sent successfully!');
        await emailService.close();

        process.exit(0);
    } catch (error) {
        logger.error('Email test failed:', error);
        process.exit(1);
    }
}
void testEmailService();
