import { Prisma, PrismaClient } from '@prisma/client';
import { PersonQueryOptions, PersonSlug } from './person.types';
const prisma = new PrismaClient();

export async function updatePersonModel(slug: PersonSlug, payload: Prisma.PersonUpdateWithoutAddressInput, options?: PersonQueryOptions) {
    return await prisma.person.update({
        data: {
            firstName: payload?.firstName,
            lastName: payload?.lastName,
            phone: payload?.phone
        },
        where: {
            slug: slug
        },
        ...options
    });
}

export default {
    updatePersonModel
};
