import { z } from 'zod';

export const detailsSchema = z.object({
    details: z.string().min(1).optional()
});

export const detailsQuerySchema = z.object({
    params: detailsSchema
});

export const getBySlugSchema = z.object({
    slug: z.string().uuid()
});

export const getBySlugParamsSchema = z.object({
    params: getBySlugSchema
});

// Type for Registration Data
export type SlugParamsSchema = z.infer<typeof getBySlugParamsSchema>;
export type SlugSchema = z.infer<typeof getBySlugSchema>;

export type DetailsQuerySchema = z.infer<typeof detailsQuerySchema>;
export type DetailsSchema = z.infer<typeof detailsSchema>;
