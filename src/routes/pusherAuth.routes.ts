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
        this.router.get("/api/chat/messages", this.controller.getMessages);
        this.router.get("/api/chat/resolve-dm", this.controller.resolveDM);
        this.router.get("/api/chat/users", this.controller.listUsers)
        this.router.get("/api/chat/last", this.controller.getLastConversation);
        this.router.post("/api/chat/mark-read", this.controller.markRead);
        this.router.get("/api/chat/unread-summary", this.controller.unreadSummary);
    }
}

export default new PusherAuthRoutes().router;