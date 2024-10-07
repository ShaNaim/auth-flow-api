import logger from 'pino';
import dayjs from 'dayjs';
import server from './config';

const log = logger({
    transport: {
        target: 'pino-pretty'
    },
    level: server.log_level,
    base: {
        pid: false
    },
    timestamp: () => `,"time": "${dayjs().format('MM-DD HH:mm:ss')}"`
});

export default log;
