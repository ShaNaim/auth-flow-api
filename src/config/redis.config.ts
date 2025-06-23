import Redis from 'ioredis';
import logger from './logger.config';

export function createRedisConnection() {
    const redis = new Redis({
        host: process.env.REDIS_HOST || 'localhost',
        port: Number(process.env.REDIS_PORT) || 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        maxRetriesPerRequest: 3,
        lazyConnect: true
    });

    redis.on('connect', () => {
        logger.info('Connected to Redis');
    });

    redis.on('error', (error) => {
        logger.error('Redis connection error:', error);
    });

    redis.on('ready', () => {
        logger.info('Redis is ready to accept commands');
    });

    redis.on('close', () => {
        logger.warn('Redis connection closed');
    });

    return redis;
}
