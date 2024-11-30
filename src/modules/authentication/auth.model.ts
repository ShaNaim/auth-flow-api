import { PrismaClient, Session, User } from '@prisma/client';
import { IdType } from '@utils/types';

const prisma = new PrismaClient();

export async function getUserForAuthentication(email: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: { email: email },
        include: {
            person: true
        }
    });
    return user ?? null;
}

export async function getUserBySlug(slug: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: { slug: slug },
        include: {
            person: true
        }
    });
    return user ?? null;
}

export async function createSession(userId: IdType<User>): Promise<Session> {
    const newSession = await prisma.session.create({
        data: {
            user: {
                connect: { id: userId }
            }
        }
    });
    return newSession ?? null;
}

export async function updateSession(sessionId: IdType<Session>, sessionData: Partial<{ isActive: boolean; isBlocked: boolean }>) {
    return await prisma.session.update({
        where: {
            id: sessionId // Ensure that `userId` is unique in the Prisma schema
        },
        data: {
            isActive: sessionData.isActive ?? undefined, // Update only if provided
            isBlocked: sessionData.isBlocked ?? undefined // Update only if provided
        }
    });
}

export async function findSessionsByUserId(userId: IdType<User>): Promise<Array<Session>> {
    return (
        (await prisma.session.findMany({
            where: {
                userId
            }
        })) ?? null
    );
}

export async function deleteSessionsByUserId(userId: IdType<User>) {
    return (
        (await prisma.session.deleteMany({
            where: {
                userId
            }
        })) ?? null
    );
}

export async function deleteSessionsById(id: number) {
    return await prisma.session.delete({
        where: {
            id
        }
    });
}
