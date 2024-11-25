declare namespace Express {
    interface Request {
        userId: number;
        jwt?: { sub: number; email: string; iat: number; issuer: string; audience: string };
    }
}
