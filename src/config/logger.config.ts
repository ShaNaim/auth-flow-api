import pino from 'pino';
import dayjs from 'dayjs';

const server = {
    log_level: process.env.LOG_LEVEL || 'info'
};

const log = pino({
    level: server.log_level,
    base: {
        pid: false
    },
    timestamp: () => `,"time":"${dayjs().format('MM-DD HH:mm:ss')}"`,
    transport: {
        targets: [
            // LogFMT transport for file logging
            {
                target: 'pino-logfmt',
                level: server.log_level,
                options: {
                    flattenNestedObjects: true,
                    convertToSnakeCase: true,
                    destination: './logs/authflow.log'
                }
            },
            // Pretty transport for console output
            {
                target: 'pino-pretty',
                level: server.log_level,
                options: {
                    colorize: true,
                    translateTime: 'SYS:standard',
                    ignore: 'pid,hostname',
                    messageFormat: '{msg} {data}',
                    singleLine: true
                }
            }
        ]
    }
});

export default log;
