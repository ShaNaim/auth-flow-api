import { z } from 'zod';
import { getBySlugSchema } from './request.validator';
// User Validator
export const userSchema = z.object({
    email: z.string().email().max(40), // Email validation
    password: z.string().min(8).max(255) // Password length between 8 and 255
});

// Person Validator
export const addressSchema = z.object({
    country: z.string().min(1), // Country name must not be empty
    city: z.string().min(1), // City name must not be empty
    district: z.string().min(1).optional(), // District must not be empty
    street: z.string().min(1), // Street must not be empty
    area: z.string().optional(), // Area is optional
    postalCode: z.number() // Postal code must be a number
});

// Person Validator
export const personSchema = z.object({
    firstName: z.string().min(1).max(255), // First name must not be empty and has a max length
    lastName: z.string().min(1).max(255).optional(), // Last name must not be empty and has a max length
    phone: z.string().min(7).max(15), // Phone number must be between 7 and 15 digits
    address: addressSchema.optional() // Reference the addressSchema directly
});

export const updateUserSchema = personSchema.partial().strict();

export const updateUserInputSchema = z.object({
    body: updateUserSchema,
    params: getBySlugSchema
});

export type UserInputSchema = z.infer<typeof userSchema>;
export type PersonInputSchema = z.infer<typeof personSchema>;
export type AddressInputSchema = z.infer<typeof addressSchema>;

export type UpdateUserInputSchema = z.infer<typeof updateUserInputSchema>;
export type UpdateUserSchema = z.infer<typeof updateUserSchema>;
