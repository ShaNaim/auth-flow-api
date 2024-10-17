import { cleanEnv, str, port, num } from 'envalid';
import { serverModes, logLevels } from '@config/server';
function validateEnv(): void {
    cleanEnv(process.env, {
        NODE_ENV: str({
            choices: Object.keys(serverModes)
        }),
        LOG_LEVEL: str({
            choices: Object.keys(logLevels)
        }),
        HOSTNAME: str(),
        PORT: port({ default: 3000 }),
        API_VERSION: num({ default: 0 })
    });
}

export default validateEnv;
