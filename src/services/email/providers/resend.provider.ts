// src/services/email/providers/resend.provider.ts

import { EmailProvider, EmailProviderConfig, SendEmailOptions, SendEmailResult } from './email-provider.types';
import logger from '@config/logger.config';
import axios from 'axios';

export interface ResendConfig extends EmailProviderConfig {
    apiKey: string;
    from: {
        name: string;
        email: string;
    };
}

export class ResendProvider extends EmailProvider {
    private resendConfig: ResendConfig;
    private baseUrl = 'https://api.resend.com';

    constructor(config: ResendConfig) {
        super(config);
        this.resendConfig = config;
    }

    async initialize(): Promise<void> {
        try {
            if (!this.enabled) {
                logger.info(`Resend provider ${this.name} is disabled`);
                return;
            }

            const isValid = await this.testConnection();
            if (!isValid) {
                throw new Error('Resend API key validation failed');
            }

            logger.info(`Resend provider ${this.name} initialized successfully`);
        } catch (error) {
            logger.error(`Failed to initialize Resend provider ${this.name}`, error);
            throw error;
        }
    }

    async sendEmail(options: SendEmailOptions): Promise<SendEmailResult> {
        try {
            const response = await axios.post(
                `${this.baseUrl}/emails`,
                {
                    from: `${this.resendConfig.from.name} <${this.resendConfig.from.email}>`,
                    to: options.to,
                    subject: options.subject,
                    html: options.html,
                    text: options.text
                },
                {
                    headers: {
                        Authorization: `Bearer ${this.resendConfig.apiKey}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            return {
                success: true,
                messageId: response.data.id,
                provider: this.name
            };
        } catch (error) {
            let errorMessage = 'Unknown error';
            if (axios.isAxiosError(error)) {
                errorMessage = error.response?.data?.message || error.message;
            }

            return {
                success: false,
                provider: this.name,
                error: errorMessage
            };
        }
    }

    async testConnection(): Promise<boolean> {
        try {
            // Resend doesn't have a specific test endpoint,
            // but we can verify the API key by checking the domains endpoint
            const response = await axios.get(`${this.baseUrl}/domains`, {
                headers: {
                    Authorization: `Bearer ${this.resendConfig.apiKey}`
                }
            });

            return response.status === 200;
        } catch (error) {
            logger.error(`Resend connection test failed for ${this.name}`, error);
            return false;
        }
    }

    async close(): Promise<void> {
        // Nothing to close for API-based provider
    }
}
