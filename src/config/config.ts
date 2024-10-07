import dotenv from 'dotenv';
dotenv.config();

export default {
    port: process.env.PORT || 3060,
    log_level: process.env.LOG_LEVEL || 'info',
    host_name: process.env.HOSTNAME
};
