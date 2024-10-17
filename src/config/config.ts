import dotenv from 'dotenv';
import validateEnv from '@utils/validator/env.validator';

dotenv.config();
validateEnv();

export default {
    port: process.env.PORT || 3060,
    log_level: process.env.LOG_LEVEL || 'info',
    host_name: process.env.HOSTNAME,
    mode: process.env.NODE_ENV,
    version: process.env.API_VERSION
};
