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

const miliseconds_in_minites = 60000;

export default {
    port: process.env.PORT || 3060,
    log_level: process.env.LOG_LEVEL || 'info',
    host_name: process.env.HOSTNAME,
    mode: process.env.NODE_ENV,
    version: process.env.API_VERSION,

    access_token_public_key: process.env.ACCESS_TOKEN_PUBLIC_KEY,
    access_token_private_key: process.env.ACCESS_TOKEN_PRIVATE_KEY,
    refresh_token_public_key: process.env.REFRESH_TOKEN_PUBLIC_KEY,
    refresh_token_private_key: process.env.REFRESH_TOKEN_PRIVATE_KEY,
    access_token_valid_time: Number(process.env.ACCESS_TOKEN_VALID_TIME) * miliseconds_in_minites,
    refresh_token_valid_time: Number(process.env.REFRESH_TOKEN_VALID_TIME) * miliseconds_in_minites
};
