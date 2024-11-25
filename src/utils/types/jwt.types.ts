export interface IJwtObject {
    accessToken: string;
    refreshToken: string;
    expiresIn?: string | number;
}

export interface IJwtPayload {
    sub: number;
    email: string;
    iat: number;
    issuer: string;
    audience: string;
}

export type IJwtPrivateKey = 'access_token_private_key' | 'refresh_token_private_key';

export type IJwtPublicKey = 'access_token_public_key' | 'refresh_token_public_key';
