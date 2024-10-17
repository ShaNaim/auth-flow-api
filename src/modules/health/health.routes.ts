import express, { Router } from 'express';
import { healthCheckController, systemCheckController } from './health.controller';
const healthRouter: Router = express.Router();

healthRouter.get('/', healthCheckController);
//TODO: make this route Protected
healthRouter.get('/system', systemCheckController);

export default healthRouter;
