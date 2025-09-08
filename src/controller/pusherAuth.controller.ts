import type { Request, Response } from "express";
import { pool } from "../db";
import { pusher } from "../pusher";
import type { SessionUser } from "../types";
import { ApiResponse } from "../model/Response/response_standard";

export default class pusherAuthController {
    //#region [Pusher Auth]
    pusherAuth = (req: Request, res: Response) => {
        const user = (req.session as any).user as SessionUser | undefined;
        if (!user) return res.status(401).send("Not authenticated");

        const { channel_name, socket_id } = req.body ?? {};
        if (typeof channel_name !== "string" || typeof socket_id !== "string") {
            return res.status(400).send("Bad request");
        }

        const isPresence = /^presence-[A-Za-z0-9_\-:.=,]+$/.test(channel_name);
        const isPrivateDM = /^private-chat-\d+-\d+$/.test(channel_name);
        if (!isPresence && !isPrivateDM) return res.status(400).send("Invalid channel");

        if (isPrivateDM) {
            const [, , aStr, bStr] = channel_name.split("-");
            const a = Number(aStr), b = Number(bStr), me = Number(user.id);
            if (Number.isNaN(a) || Number.isNaN(b)) return res.status(400).send("Invalid channel ids");
            if (me !== a && me !== b) return res.status(403).send("Forbidden");
        }

        const presenceData = {
            user_id: String(user.id),
            user_info: {
                id: Number(user.id),
                username: user.username,
                fullname: user.fullname,
                isAdmin: !!user.isAdmin,
            },
        };

        const auth = pusher.authorizeChannel(socket_id, channel_name, presenceData);
        return res.send(auth);
    };
    //#endregion

    //#region [Chat Send via Pusher]
    sendChat = async (req: Request, res: Response<ApiResponse>) => {
        const user = (req.session as any).user as SessionUser | undefined;
        if (!user) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });

        const { room, text } = req.body ?? {};
        if (typeof room !== "string" || typeof text !== "string") {
            return res.status(400).json({ success: false, message: "Bad request", statusCode: 400 });
        }

        const isPresence = /^presence-[A-Za-z0-9_\-:.=,]+$/.test(room);
        const isDM = /^private-chat-\d+-\d+$/.test(room);
        if (!isPresence && !isDM) return res.status(400).json({ success: false, message: "Invalid room", statusCode: 400 });

        if (isDM) {
            const [, , aStr, bStr] = room.split("-");
            const a = Number(aStr), b = Number(bStr), me = Number(user.id);
            if (me !== a && me !== b) return res.status(403).json({ success: false, message: "Forbidden", statusCode: 403 });
        }

        const payload = { from: user.username, text: text.trim(), at: Date.now() };
        await pusher.trigger(room, "message", payload);
        return res.json({ success: true, message: "Message sent", statusCode: 200 });
    };
    //#endregion

    //#region [List Users]
    listUsers = async (req: Request, res: Response<ApiResponse>) => {
        const me = (req.session as any).user as SessionUser | undefined;
        if (!me) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });

        const [rows] = await pool.query(
            "SELECT id, username, fullname FROM accounts ORDER BY fullname ASC"
        );
        return res.json({ success: true, data: { users: rows as any[] }, message: "OK", statusCode: 200 });
    };
    //#endregion
}