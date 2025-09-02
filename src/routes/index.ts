import express from 'express';
import SignInRoutes from './signin.routes';

const router = express.Router();
router.use(SignInRoutes);


export default router;