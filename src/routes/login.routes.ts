import { Router } from "express";
import LoginController from "../controller/login.controller";

class SignInRoutes {
    router = Router();
    controller = new LoginController();

    constructor() {
        this.intializeRoutes();
    }

    intializeRoutes() {
        this.router.post("/register", this.controller.Register);
        this.router.post("/login", this.controller.login);
        this.router.get("/me", this.controller.me);
        this.router.post("/forgot-password", this.controller.ForgotPassword);
        this.router.post("/reset-password", this.controller.ResetPassword);
        this.router.post("/logout", this.controller.logout);
    }
}

export default new SignInRoutes().router;