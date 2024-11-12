import express, { Router } from 'express';
import { healthController } from './controller';

const userRouter: Router = express.Router();

userRouter.get('/health', healthController);

export default userRouter;
