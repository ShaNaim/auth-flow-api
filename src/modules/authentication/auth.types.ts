import { User, Person } from '@prisma/client';
// Type definitions
export type UserWithPerson = User & {
    person: Person | null;
};

export interface SessionUpdateData {
    isActive?: boolean;
    isBlocked?: boolean;
}

export interface StoreRefreshTokenParams {
    userId: number;
    tokenHash: string;
    userAgent: string;
    ip: string | null;
    expiresAt: Date;
}

export interface RotateRefreshTokenParams {
    userId: number;
    oldTokenHash: string;
    newTokenHash: string;
    userAgent: string;
    ip: string;
    expiresAt: Date;
}
