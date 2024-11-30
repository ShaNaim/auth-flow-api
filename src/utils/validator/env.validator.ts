import { cleanEnv, str, port, num } from 'envalid';
import { serverModes, logLevels } from '@config/server.config';

function validateEnv(): void {
    cleanEnv(process.env, {
        NODE_ENV: str({
            choices: Object.keys(serverModes)
        }),
        LOG_LEVEL: str({
            choices: Object.keys(logLevels)
        }),
        HOSTNAME: str(),
        DATABASE_URL: str(),
        PORT: port({ default: 3000 }),
        API_VERSION: num({ default: 1 }),
        ACCESS_TOKEN_VALID_TIME: num({ default: 1 }),
        REFRESH_TOKEN_VALID_TIME: num({ default: 1 }),
        ACCESS_TOKEN_PUBLIC_KEY: str(),
        ACCESS_TOKEN_PRIVATE_KEY: str(),
        REFRESH_TOKEN_PUBLIC_KEY: str(),
        REFRESH_TOKEN_PRIVATE_KEY: str()
    });
}

export default validateEnv;
