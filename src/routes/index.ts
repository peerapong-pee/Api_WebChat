import express from 'express';
import SignInRoutes from './login.routes';
import PusherAuthRoutes from './pusherAuth.routes';

const router = express.Router();
router.use(SignInRoutes);
router.use(PusherAuthRoutes)


export default router;