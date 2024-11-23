import dotenv from 'dotenv';
import validateEnv from '@utils/validator/env.validator';

dotenv.config();
validateEnv();

export const tokenTypes = {
    access_token_public_key: 'access_token_public_key',
    access_token_private_key: 'access_token_private_key',
    refresh_token_public_key: 'refresh_token_public_key',
    refresh_token_private_key: 'refresh_token_private_key'
};

export const server = {};

export default {
    port: process.env.PORT || 3060,
    log_level: process.env.LOG_LEVEL || 'info',
    host_name: process.env.HOSTNAME,
    mode: process.env.NODE_ENV,
    version: process.env.API_VERSION,
    access_token_public_key: process.env.ACCESS_TOKEN_PUBLIC_KEY || 'a',
    access_token_private_key: process.env.ACCESS_TOKEN_PRIVATE_KEY || 'a',
    refresh_token_public_key: process.env.REFRESH_TOKEN_PUBLIC_KEY || 'a',
    refresh_token_private_key: process.env.REFRESH_TOKEN_PRIVATE_KEY || 'a'
};
