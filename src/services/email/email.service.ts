import logger from '@config/logger.config';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
import axios from 'axios';
import {
    AccountBlockedTemplateData,
    BaseTemplateData,
    PasswordResetTemplateData,
    SendEmailOptions,
    VerificationTemplateData,
    WelcomeTemplateData
} from './email.types';

class EmailService {
    private apiKey: string;
    private fromEmail: string;
    private fromName: string;
    private baseUrl = 'https://api.resend.com';
    private isInitialized: boolean = false;

    constructor() {
        this.apiKey = process.env.RESEND_API_KEY || '';
        this.fromEmail = process.env.EMAIL_FROM_ADDRESS || 'noreply@authflow.com';
        this.fromName = process.env.EMAIL_FROM_NAME || 'Auth Flow API';
    }

    /**
     * Initialize the email service
     */
    async initialize(): Promise<void> {
        if (this.isInitialized) {
            logger.warn('Email service already initialized');
            return;
        }

        try {
            logger.info('Initializing Resend email service...');

            if (!this.apiKey) {
                throw new Error('Resend API key not configured');
            }

            // Test the connection
            const isValid = await this.testConnection();
            if (!isValid) {
                throw new Error('Resend API key validation failed');
            }

            this.isInitialized = true;
            logger.info('Resend email service initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize email service', error);
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Failed to initialize email service',
                data: {
                    path: ['email', 'service', 'initialize'],
                    message: error instanceof Error ? error.message : 'Unknown error'
                },
                isOperational: false
            });
        }
    }

    /**
     * Send an email using Resend
     */
    private async sendEmail(options: SendEmailOptions): Promise<string> {
        if (!this.isInitialized) {
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Email service not initialized',
                data: {
                    path: ['email', 'service', 'sendEmail'],
                    message: 'Call initialize() before sending emails'
                }
            });
        }

        try {
            const response = await axios.post(
                `${this.baseUrl}/emails`,
                {
                    from: `${this.fromName} <${this.fromEmail}>`,
                    to: options.to,
                    subject: options.subject,
                    html: options.html,
                    text: options.text || this.stripHtml(options.html)
                },
                {
                    headers: {
                        Authorization: `Bearer ${this.apiKey}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            logger.info('Email sent successfully', {
                messageId: response.data.id,
                to: options.to,
                subject: options.subject
            });

            return response.data.id;
        } catch (error) {
            logger.error('Failed to send email', error);

            let errorMessage = 'Unknown error';
            if (axios.isAxiosError(error)) {
                errorMessage = error.response?.data?.message || error.message;
            }

            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Failed to send email',
                data: {
                    path: ['email', 'service', 'sendEmail'],
                    message: errorMessage
                }
            });
        }
    }

    /**
     * Test Resend connection
     */
    async testConnection(): Promise<boolean> {
        try {
            const response = await axios.get(`${this.baseUrl}/domains`, {
                headers: {
                    Authorization: `Bearer ${this.apiKey}`
                }
            });
            return response.status === 200;
        } catch (error) {
            logger.error('Resend connection test failed', error);
            return false;
        }
    }

    /**
     * Simple HTML to text conversion
     */
    private stripHtml(html: string): string {
        return html
            .replace(/<[^>]*>/g, '')
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&#039;/g, "'")
            .trim();
    }

    /**
     * Replace template variables
     */
    private replaceTemplateVariables(template: string, data: Record<string, any>): string {
        return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            return data[key] || match;
        });
    }

    /**
     * Get base template data
     */
    private getBaseTemplateData(firstName: string): BaseTemplateData {
        return {
            firstName,
            appName: process.env.APP_NAME || 'Auth Flow',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            year: new Date().getFullYear()
        };
    }

    /**
     * Send welcome email
     */
    async sendWelcomeEmail(to: string, data: { firstName: string; verificationToken?: string }): Promise<string> {
        const templateData: WelcomeTemplateData = {
            ...this.getBaseTemplateData(data.firstName),
            verificationUrl: data.verificationToken ? `${process.env.APP_URL}/verify?token=${data.verificationToken}` : undefined
        };

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f4f4f4; }
                    .button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }
                    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Welcome to {{appName}}!</h1>
                    </div>
                    <div class="content">
                        <h2>Hi {{firstName}},</h2>
                        <p>Thank you for signing up! We're excited to have you on board.</p>
                        ${
                            templateData.verificationUrl
                                ? `
                        <p>Please verify your email address by clicking the button below:</p>
                        <p style="text-align: center;">
                            <a href="{{verificationUrl}}" class="button">Verify Email</a>
                        </p>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all;">{{verificationUrl}}</p>
                        `
                                : ''
                        }
                        <p>If you have any questions, feel free to reach out to our support team.</p>
                        <p>Best regards,<br>The {{appName}} Team</p>
                    </div>
                    <div class="footer">
                        <p>&copy; {{year}} {{appName}}. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;

        const processedHtml = this.replaceTemplateVariables(html, templateData);

        return await this.sendEmail({
            to,
            subject: `Welcome to ${templateData.appName}!`,
            html: processedHtml
        });
    }

    /**
     * Send password reset email
     */
    async sendPasswordResetEmail(to: string, data: { firstName: string; resetToken: string }): Promise<string> {
        const templateData: PasswordResetTemplateData = {
            ...this.getBaseTemplateData(data.firstName),
            resetUrl: `${process.env.APP_URL}/reset-password?token=${data.resetToken}`,
            expiryTime: '1 hour'
        };

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #ff9800; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f4f4f4; }
                    .button { display: inline-block; padding: 10px 20px; background-color: #ff9800; color: white; text-decoration: none; border-radius: 5px; }
                    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Password Reset Request</h1>
                    </div>
                    <div class="content">
                        <h2>Hi {{firstName}},</h2>
                        <p>We received a request to reset your password. Click the button below to create a new password:</p>
                        <p style="text-align: center;">
                            <a href="{{resetUrl}}" class="button">Reset Password</a>
                        </p>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all;">{{resetUrl}}</p>
                        <div class="warning">
                            <p><strong>Important:</strong> This link will expire in {{expiryTime}}.</p>
                        </div>
                        <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
                        <p>Best regards,<br>The {{appName}} Team</p>
                    </div>
                    <div class="footer">
                        <p>&copy; {{year}} {{appName}}. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;

        const processedHtml = this.replaceTemplateVariables(html, templateData);

        return await this.sendEmail({
            to,
            subject: 'Password Reset Request',
            html: processedHtml
        });
    }

    /**
     * Send verification email
     */
    async sendVerificationEmail(to: string, data: { firstName: string; verificationToken: string }): Promise<string> {
        const templateData: VerificationTemplateData = {
            ...this.getBaseTemplateData(data.firstName),
            verificationUrl: `${process.env.APP_URL}/verify?token=${data.verificationToken}`
        };

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #2196F3; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f4f4f4; }
                    .button { display: inline-block; padding: 10px 20px; background-color: #2196F3; color: white; text-decoration: none; border-radius: 5px; }
                    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Verify Your Email</h1>
                    </div>
                    <div class="content">
                        <h2>Hi {{firstName}},</h2>
                        <p>Please verify your email address to complete your registration.</p>
                        <p style="text-align: center;">
                            <a href="{{verificationUrl}}" class="button">Verify Email</a>
                        </p>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all;">{{verificationUrl}}</p>
                        <p>Best regards,<br>The {{appName}} Team</p>
                    </div>
                    <div class="footer">
                        <p>&copy; {{year}} {{appName}}. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;

        const processedHtml = this.replaceTemplateVariables(html, templateData);

        return await this.sendEmail({
            to,
            subject: 'Verify Your Email Address',
            html: processedHtml
        });
    }

    /**
     * Send account blocked email
     */
    async sendAccountBlockedEmail(to: string, data: { firstName: string; reason?: string }): Promise<string> {
        const templateData: AccountBlockedTemplateData = {
            ...this.getBaseTemplateData(data.firstName),
            reason: data.reason || 'violations of our terms of service',
            supportEmail: process.env.SUPPORT_EMAIL || 'support@authflow.com'
        };

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #f44336; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f4f4f4; }
                    .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Account Blocked</h1>
                    </div>
                    <div class="content">
                        <h2>Hi {{firstName}},</h2>
                        <p>We regret to inform you that your account has been blocked due to {{reason}}.</p>
                        <p>If you believe this is a mistake or would like to appeal this decision, please contact our support team at <a href="mailto:{{supportEmail}}">{{supportEmail}}</a>.</p>
                        <p>Best regards,<br>The {{appName}} Team</p>
                    </div>
                    <div class="footer">
                        <p>&copy; {{year}} {{appName}}. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;

        const processedHtml = this.replaceTemplateVariables(html, templateData);

        return await this.sendEmail({
            to,
            subject: 'Account Blocked',
            html: processedHtml
        });
    }

    /**
     * Close the email service (for Resend, nothing to close)
     */
    // eslint-disable-next-line require-await, @typescript-eslint/require-await
    async close(): Promise<void> {
        this.isInitialized = false;
        logger.info('Email service closed');
    }
}

// Export singleton instance
export const emailService = new EmailService();

// Export initialization function
export async function initializeEmailService(): Promise<void> {
    await emailService.initialize();
}
