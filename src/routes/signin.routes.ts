import { Router } from "express";
import SigninController from "../controller/signin.controller";

class SignInRoutes {
    router = Router();
    controller = new SigninController();

    constructor() {
        this.intializeRoutes();
    }

    intializeRoutes() {
        this.router.post("/register", this.controller.Register);

    }
}

export default new SignInRoutes().router;