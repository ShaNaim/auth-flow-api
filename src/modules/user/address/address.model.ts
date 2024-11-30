import { Address, Prisma, PrismaClient } from '@prisma/client';
import { AddressSlug, AddressQueryOptions } from './address.types';

const prisma = new PrismaClient();

async function updateAddress(slug: AddressSlug, payload: Prisma.AddressUpdateInput, options?: AddressQueryOptions): Promise<Address> {
    return await prisma.address.update({
        data: {
            country: payload?.country,
            district: payload?.district,
            city: payload?.city,
            area: payload?.area,
            street: payload?.street,
            postalCode: payload?.postalCode
        },
        where: {
            slug: slug
        },
        ...options
    });
}

const addressModel = { updateAddress };
export default addressModel;
