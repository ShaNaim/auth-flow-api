import { PrismaClient, User } from '@prisma/client';
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
