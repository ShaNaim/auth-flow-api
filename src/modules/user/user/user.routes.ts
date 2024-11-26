import express, { Router } from 'express';
import * as userController from './user.controller';
import requestValidator from '@middlewares/requestValidator';
import { registerInputSchema, getBySlugParamsSchema } from '@utils/validator/requestSchemaValidator';
import { tokenRequired } from '@middlewares/tokenHandler';

const userRouter: Router = express.Router();

userRouter.get('/health', [tokenRequired], userController.healthController);
userRouter.post('/', [tokenRequired, requestValidator(registerInputSchema)], userController.createUser);
userRouter.get('/me', [tokenRequired], userController.healthController);
userRouter.put('/block/:slug', [tokenRequired], userController.healthController);
userRouter.get('/:slug', [tokenRequired, requestValidator(getBySlugParamsSchema)], userController.getUserbySlug);

export default userRouter;
