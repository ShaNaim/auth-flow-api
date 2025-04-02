import express, { Router } from 'express';
import requestValidator from '@middlewares/requestValidator';
import { registerInputSchema, loginInputSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';
import * as authController from './auth.controller';
import { tokenRequired, csrfHandlerMiddleware } from '@middlewares/tokenHandler';
import { getBySlugParamsSchema } from '@utils/validator/requestSchemaValidator';
const authRouter: Router = express.Router();

authRouter.get('/health', authController?.healthController);
authRouter.get('/check/public', authController?.healthController);
authRouter.get('/check/private', [tokenRequired], authController?.healthController);
authRouter.post('/check/csrf', [csrfHandlerMiddleware], authController?.healthController);

authRouter.post('/login', [requestValidator(loginInputSchema)], authController?.loginController);
authRouter.post('/register', [requestValidator(registerInputSchema)], authController?.registerController);
authRouter.get('/logout', [tokenRequired], authController?.logoutController);
authRouter.put('/block/:slug', [tokenRequired, requestValidator(getBySlugParamsSchema)], authController.blockUserController);

export default authRouter;
