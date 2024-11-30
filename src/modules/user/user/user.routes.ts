import express, { Router } from 'express';
import * as userController from './user.controller';
import requestValidator from '@middlewares/requestValidator';
import { registerInputSchema, getBySlugParamsSchema, updateUserInputSchema } from '@utils/validator/requestSchemaValidator';
import { tokenRequired } from '@middlewares/tokenHandler';

const userRouter: Router = express.Router();

userRouter.get('/health', [tokenRequired], userController.healthController);

userRouter.get('/', [tokenRequired], userController.getAllUsersController);

userRouter.post('/', [tokenRequired, requestValidator(registerInputSchema)], userController.createUser);
userRouter.put('/:slug', [tokenRequired, requestValidator(updateUserInputSchema)], userController.updateUserController);
userRouter.get('/me', [tokenRequired], userController.getAuthenticatedUserInfo);
userRouter.get('/:slug', [tokenRequired, requestValidator(getBySlugParamsSchema)], userController.getUserbySlug);

export default userRouter;
