import { PrismaClient, Session, User } from '@prisma/client';
import { IdType } from '@utils/types';

const prisma = new PrismaClient();
export async function getUserForAuthentication(email: string): Promise<User | null> {
    try {
        const user = await prisma.user.findUnique({
            where: { email: email },
            include: {
                person: true
            }
        });
        return user ?? null;
    } catch (error) {
        throw error;
    }
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
