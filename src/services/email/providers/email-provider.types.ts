// src/services/email/providers/email-provider.interface.ts

export interface EmailProviderConfig {
    name: string;
    priority: number;
    enabled: boolean;
}

export interface SendEmailOptions {
    to: string;
    subject: string;
    html: string;
    text?: string;
    attachments?: Array<{
        filename: string;
        content?: Buffer | string;
        path?: string;
    }>;
}

export interface SendEmailResult {
    success: boolean;
    messageId?: string;
    provider: string;
    error?: string;
}

export abstract class EmailProvider {
    protected config: EmailProviderConfig;

    constructor(config: EmailProviderConfig) {
        this.config = config;
    }

    abstract initialize(): Promise<void>;
    abstract sendEmail(options: SendEmailOptions): Promise<SendEmailResult>;
    abstract testConnection(): Promise<boolean>;
    abstract close(): Promise<void>;

    get name(): string {
        return this.config.name;
    }

    get priority(): number {
        return this.config.priority;
    }

    get enabled(): boolean {
        return this.config.enabled;
    }
}
