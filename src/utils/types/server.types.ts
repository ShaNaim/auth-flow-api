import { Request } from 'express';

export type Uptime = { original: number; formattedUptime: string };
export type RequestType<ReqBody, Params = unknown, Query = unknown, ResBody = unknown> = Request<Params, ResBody, ReqBody, Query>;
export type IdType<T> = T extends { id: infer U } ? U : never;
export type SlugType<T> = T extends { slug: infer U } ? U : never;
