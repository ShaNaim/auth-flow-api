import { Request, Response } from 'express';
import os from 'os';
import { responseObject } from '@provider/response.provider';
import { Uptime } from '@utils/types/server.types';

export function healthCheckController(req: Request, res: Response) {
    res.status(200).json(
        responseObject(
            {
                message: 'System Running , Health OK'
            },
            false
        )
    );
}

export function systemCheckController(_: Request, res: Response) {
    res.status(200).json(
        responseObject(
            {
                message: `System Running on ${os.type()} || Platform : ${os.platform()}`,
                freeMemory: `${Math.round(os.freemem() / 1024 ** 2)} MB`,
                architecture: os.arch(),
                uptime: getTotalUptime()
            },
            false
        )
    );
}

function getTotalUptime(): Uptime {
    const uptimeInSeconds = os.uptime();
    const hours = Math.floor(uptimeInSeconds / 3600);
    const minutes = Math.floor((uptimeInSeconds % 3600) / 60);
    const seconds = Math.floor(uptimeInSeconds % 60);
    const formattedUptime = `${hours} hr ${minutes} min ${seconds} sec`;
    return {
        original: uptimeInSeconds,
        formattedUptime
    };
}
