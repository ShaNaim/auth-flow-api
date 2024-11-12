import { Router } from 'express';
import healthRouter from '@modules/health/health.routes';
import authRouter from '@modules/authentication/auth.routes';
import userModuleRouter from '@modules/user/router';

const router: Router = Router();

router.use('/health', healthRouter);
router.use('/auth', authRouter);
router.use(userModuleRouter);

export default router;
