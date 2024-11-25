import { z } from 'zod';
import { addressSchema } from './user.validator';

// Token Validator
export const tokenSchema = z.object({
    accessToken: z.string().min(1).max(255), // Access token must not be empty
    refreshToken: z.string().min(1).max(255), // Refresh token must not be empty
    userId: z.number(), // Foreign key to User
    isActive: z.boolean().default(true), // Default value for isActive
    accessTokenValidityTime: z.date(), // Access token expiry date
    refreshTokenValidityTime: z.date(), // Refresh token expiry date
    isBlocked: z.boolean().default(false) // Default value for isBlocked
});

const registerSchema = z.object({
    email: z.string().email().max(40), // Email validation
    password: z.string().min(8).max(255), // Password length between 8 and 255
    firstName: z.string().min(1).max(255), // First name must not be empty and has a max length
    lastName: z.string().min(1).max(255).optional(), // Last name must not be empty and has a max length
    phone: z.string().min(7).max(15), // Phone number must be between 7 and 15 digits
    address: addressSchema.optional() // Reference the addressSchema directly
});

export const registerInputSchema = z.object({
    body: registerSchema
});

export const loginSchema = z.object({
    email: z.string().email().max(40), // Email validation
    password: z.string().max(255) // Password maximum 255 char
});
export const loginInputSchema = z.object({
    body: loginSchema
});

// Type for Registration Data
export type RegisterInputSchema = z.infer<typeof registerInputSchema>;
export type RegisterSchema = z.infer<typeof registerSchema>;

export type TokenInputSchema = z.infer<typeof tokenSchema>;
export type LoginInputSchema = z.infer<typeof loginInputSchema>;
export type LoginSchema = z.infer<typeof loginSchema>;
