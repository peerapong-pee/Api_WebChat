import { Router } from "express";
import pusherAuthController from "../controller/pusherAuth.controller";

class PusherAuthRoutes {
    router = Router();
    controller = new pusherAuthController();

    constructor() {
        this.intializeRoutes();
    }

    intializeRoutes() {
        this.router.post("/pusher/auth", this.controller.pusherAuth);
        this.router.post("/api/chat/send", this.controller.sendChat);
        this.router.get("/users", this.controller.listUsers);
    }
}

export default new PusherAuthRoutes().router;