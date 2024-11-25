import { Request, Response } from 'express';
import os from 'os';
import { responseObject } from '@provider/response.provider';
import { Uptime } from '@utils/types/server.types';
import { millisecondsToStrAI } from '@utils/handle-format';
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
    return {
        original: os.uptime(),
        formattedUptime: millisecondsToStrAI(os.uptime())
    };
}
