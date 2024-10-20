import { Router } from 'express';
import healthRouter from '@modules/health/health.routes';
import authRouter from '@modules/authentication/auth.routes';

const router: Router = Router();

router.use('/health', healthRouter);
router.use('/auth', authRouter);

export default router;
