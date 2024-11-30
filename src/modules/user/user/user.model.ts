import { StatusCodes } from 'http-status-codes';
import { PrismaClient, User, Prisma } from '@prisma/client';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { UserIdType, CreateUserInputDTO, UserDTO, UserQueryOptions, CreateUserDTO } from './user.types';

const prisma = new PrismaClient();

async function createUser(userInput: CreateUserInputDTO, options?: UserQueryOptions): Promise<CreateUserDTO> {
    const { email, password, firstName, lastName, phone, address } = userInput;

    return await prisma.user.create({
        data: {
            email,
            password,
            person:
                firstName || lastName || phone || address
                    ? {
                          create: {
                              firstName,
                              lastName,
                              phone,
                              address: address
                                  ? {
                                        create: {
                                            city: address.city,
                                            street: address.street,
                                            postalCode: address.postalCode,
                                            country: address.country
                                        }
                                    }
                                  : undefined
                          }
                      }
                    : undefined
        },
        ...options
    });
}

async function updateUser(id: UserIdType, userPayload: Prisma.UserUpdateInput): Promise<User> {
    try {
        const user = getUser({ id });
        if (!user)
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: 'No User Found',
                data: {
                    path: ['user', 'id'],
                    message: `No user found with ID:${id}`
                }
            });
        return await prisma.user.update({
            data: {
                email: userPayload?.email ?? userPayload.email,
                password: userPayload?.password ?? userPayload.password,
                isBlocked: userPayload?.isBlocked ?? !userPayload?.isBlocked
            },
            where: { id: id }
        });
    } catch (error) {
        throw error;
    }
}

async function getUser(query: Prisma.UserWhereUniqueInput, options?: UserQueryOptions): Promise<UserDTO | null> {
    try {
        const user = await prisma.user.findUnique({
            where: query,
            ...options
        });
        return user ?? null;
    } catch (error) {
        throw error;
    }
}

async function getAllUsers(options?: UserQueryOptions): Promise<Array<UserDTO>> {
    try {
        const users = await prisma.user.findMany({ ...options });
        return users;
    } catch (error) {
        throw error;
    }
}

export const userModel = {
    getUser,
    createUser,
    updateUser,
    getAllUsers
};
