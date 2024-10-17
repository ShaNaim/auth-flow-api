import { Router } from 'express';
import healthRouter from '@modules/health/health.routes';

const router: Router = Router();

router.use('/health', healthRouter);

export default router;
