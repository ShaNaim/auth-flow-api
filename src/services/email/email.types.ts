export interface SendEmailOptions {
    to: string;
    subject: string;
    html: string;
    text?: string;
}

// Template data interfaces
export interface BaseTemplateData {
    firstName: string;
    appName: string;
    appUrl: string;
    year: number;
}

export interface WelcomeTemplateData extends BaseTemplateData {
    verificationUrl?: string;
}

export interface PasswordResetTemplateData extends BaseTemplateData {
    resetUrl: string;
    expiryTime: string;
}

export interface VerificationTemplateData extends BaseTemplateData {
    verificationUrl: string;
}

export interface AccountBlockedTemplateData extends BaseTemplateData {
    reason?: string;
    supportEmail: string;
}
