import { z } from 'zod';

export const getBySlugSchema = z.object({
    slug: z.string().uuid()
});

export const getBySlugParamsSchema = z.object({
    params: getBySlugSchema
});

// Type for Registration Data
export type SlugParamsSchema = z.infer<typeof getBySlugParamsSchema>;
export type SlugSchema = z.infer<typeof getBySlugSchema>;
