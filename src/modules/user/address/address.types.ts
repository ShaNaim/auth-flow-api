import { Address, Prisma } from '@prisma/client';
import { IdType, SlugType } from '@utils/types';
export type AddressId = IdType<Address>;
export type AddressSlug = SlugType<Address>;

export type AddressQueryOptions = {
    select?: Prisma.AddressSelect;
    include?: Prisma.AddressInclude;
};
