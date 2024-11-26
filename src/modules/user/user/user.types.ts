import { Address, Person, Prisma, User } from '@prisma/client';
import { UserInputSchema, PersonInputSchema } from '@utils/validator/requestSchemaValidator/user.validator';
import { IdType, SlugType } from '@utils/types';

export type UserIdType = IdType<User>;
export type UserSlugType = SlugType<User>;

export type UserQueryOptions = {
    select?: Prisma.UserSelect;
    include?: Prisma.UserInclude;
};

export interface CreateUserInputDTO extends UserInputSchema, PersonInputSchema {}
export interface CreateUserDTO extends Partial<UserInputSchema>, Partial<PersonInputSchema> {}

export interface UpdateUserDTO extends Prisma.UserUpdateInput {
    id: number;
}

export type UserDTO = User & {
    person?:
        | (Omit<Person, 'userId' | 'user'> & {
              address?: Omit<Address, 'personId'> | null;
          })
        | null;
};

/// Redirects ///
export { UserInputSchema } from '@utils/validator/requestSchemaValidator/user.validator';
