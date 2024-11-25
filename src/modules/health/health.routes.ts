import express, { Router } from 'express';
import { healthCheckController, systemCheckController } from './health.controller';
import { tokenRequired } from '@middlewares/tokenHandler';
const healthRouter: Router = express.Router();

healthRouter.get('/', healthCheckController);
healthRouter.get('/system', tokenRequired, systemCheckController);

export default healthRouter;
