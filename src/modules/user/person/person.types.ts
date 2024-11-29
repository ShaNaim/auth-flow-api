import { Person, Prisma } from '@prisma/client';
import { IdType, SlugType } from '@utils/types';
export type PersonId = IdType<Person>;
export type PersonSlug = SlugType<Person>;

export type PersonQueryOptions = {
    select?: Prisma.PersonSelect;
    include?: Prisma.PersonInclude;
};

export { PersonQueryType, personQueryTypes } from '@utils/types';
