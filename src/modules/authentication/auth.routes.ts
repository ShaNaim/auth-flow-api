import express, { Router } from 'express';
import requestValidator from '@middlewares/requestValidator';
import { registerInputSchema, loginInputSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';
import { healthController, loginController, reginsterController } from './auth.controller';

const authRouter: Router = express.Router();

authRouter.get('/health', healthController);
//TODO: make this route Protected
authRouter.post('/login', [requestValidator(loginInputSchema)], loginController);
authRouter.post('/register', [requestValidator(registerInputSchema)], reginsterController);

export default authRouter;
