import { StatusCodes } from 'http-status-codes';
import { Prisma, User } from '@prisma/client';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { UpdateUserDTO, CreateUserInputDTO, UserIdType, UserSlugType, UserDTO, CreateUserDTO } from './user.types';
import { userModel } from './user.model';
import { generateUserQuery } from '@utils/provider';
// import handleError from '@errors/error.handler';

export async function createUserService(payload: CreateUserInputDTO, details: boolean = true): Promise<Omit<CreateUserDTO, 'password'>> {
    try {
        return await userModel.createUser(payload, generateUserQuery(details));
    } catch (error) {
        throw error;
    }
}

export async function updateUser(payload: UpdateUserDTO): Promise<User> {
    try {
        return await userModel.updateUser(payload?.id, payload);
    } catch (error) {
        throw error;
    }
}

export async function getUserbyId(userId: UserIdType): Promise<UserDTO | null> {
    try {
        const user = await userModel.getUser({ id: userId }, generateUserQuery(true));
        if (!user)
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: 'No User Found',
                data: {
                    path: ['user', 'id'],
                    message: `No user found with ID:${userId}`
                }
            });
        return user ?? null;
    } catch (error) {
        throw error;
    }
}

export async function getUserbyEmail(email: string, details: boolean = false): Promise<Omit<UserDTO, 'password'> | null> {
    try {
        const user = await userModel.getUser({ email: email }, generateUserQuery(details));
        return user ?? null;
    } catch (error) {
        throw error;
    }
}

export async function getUserInfobySlug(slug: UserSlugType, details: boolean = false): Promise<Omit<UserDTO, 'password'>> {
    try {
        if (!slug)
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: 'No Slug Found',
                data: {
                    path: ['user', 'slug'],
                    message: `No slug provided`
                }
            });
        const user = await userModel.getUser({ slug: slug }, generateUserQuery(details));
        if (!user)
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: 'No User Found',
                data: {
                    path: ['user', 'id'],
                    message: `No user found with ID:${slug}`
                }
            });
        return user;
    } catch (error) {
        throw error;
    }
}

export async function getUser(query: Prisma.UserWhereUniqueInput): Promise<UserDTO | null> {
    try {
        const user = await userModel.getUser(query);
        if (!user) return null;
        return user;
    } catch (error) {
        throw error;
    }
}

export async function getAllUsers(details: boolean = true): Promise<Array<UserDTO>> {
    return await userModel.getAllUsers(generateUserQuery(details));
}

// Services has can be accessed from outside modules
const userServices = { updateUser, getUserInfobySlug, createUserService, getUserbyEmail, getAllUsers };
export default userServices;
