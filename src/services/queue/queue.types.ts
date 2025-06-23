// Queue names enum for type safety
export enum QueueName {
    EMAIL = 'email',
    USER_CLEANUP = 'user-cleanup',
    REPORT_GENERATION = 'report-generation'
}

// Job names for each queue
export enum EmailJobName {
    WELCOME = 'welcome-email',
    PASSWORD_RESET = 'password-reset-email',
    VERIFICATION = 'verification-email',
    ACCOUNT_BLOCKED = 'account-blocked-email'
}

// Base job data interface
export interface BaseJobData {
    userId?: number;
    timestamp?: number;
}

// Email job data interfaces
export interface WelcomeEmailData extends BaseJobData {
    email: string;
    firstName: string;
    verificationToken?: string;
}

export interface PasswordResetEmailData extends BaseJobData {
    email: string;
    firstName: string;
    resetToken: string;
    resetUrl: string;
}

export interface VerificationEmailData extends BaseJobData {
    email: string;
    firstName: string;
    verificationToken: string;
    verificationUrl: string;
}

export interface AccountBlockedEmailData extends BaseJobData {
    email: string;
    firstName: string;
    reason?: string;
}

// Type mapping for job data
export type EmailJobData =
    | { name: EmailJobName.WELCOME; data: WelcomeEmailData }
    | { name: EmailJobName.PASSWORD_RESET; data: PasswordResetEmailData }
    | { name: EmailJobName.VERIFICATION; data: VerificationEmailData }
    | { name: EmailJobName.ACCOUNT_BLOCKED; data: AccountBlockedEmailData };
