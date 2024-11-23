import express, { Router } from 'express';
import userRouter from './user/user.routes';

const userModuleRouter: Router = express.Router();

userModuleRouter.use('/user', userRouter);

export default userModuleRouter;
