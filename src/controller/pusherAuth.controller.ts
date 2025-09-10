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
                firstname: user.firstname,
                lastname: user.lastname,
                isAdmin: !!user.isAdmin,
            },
        };

        const auth = pusher.authorizeChannel(socket_id, channel_name, presenceData);
        return res.send(auth);
    };
    //#endregion

    //#region [Chat Send via Pusher + Save DB]
    sendChat = async (req: Request, res: Response<ApiResponse>) => {
        const user = (req.session as any).user as SessionUser | undefined;
        if (!user) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });

        const { room, text, attachments } = req.body ?? {};
        if (typeof room !== "string" || typeof text !== "string") {
            return res.status(400).json({ success: false, message: "Bad request", statusCode: 400 });
        }

        const isPresence = /^presence-[A-Za-z0-9_\-:.=,]+$/.test(room);
        const isDM = /^private-chat-\d+-\d+$/.test(room);
        if (!isPresence && !isDM) {
            return res.status(400).json({ success: false, message: "Invalid room", statusCode: 400 });
        }

        // 1) หา conversation_id
        let conversationId: number | null = null;

        if (isDM) {
            const [, , aStr, bStr] = room.split("-");
            const a = Number(aStr), b = Number(bStr);
            const me = Number(user.id);
            if (Number.isNaN(a) || Number.isNaN(b)) {
                return res.status(400).json({ success: false, message: "Invalid room ids", statusCode: 400 });
            }
            if (me !== a && me !== b) {
                return res.status(403).json({ success: false, message: "Forbidden", statusCode: 403 });
            }

            // ensure DM conversation exists
            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();

                // ลองหา
                const [found] = await conn.query<any[]>(
                    `SELECT c.id
         FROM conversations c
         JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = LEAST(?, ?)
         JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = GREATEST(?, ?)
         WHERE c.type = 'dm'
         LIMIT 1`,
                    [a, b, a, b]
                );

                if (found.length > 0) {
                    conversationId = found[0].id;
                } else {
                    // สร้างใหม่
                    const [insConv] = await conn.query<any>(
                        `INSERT INTO conversations (type, created_by) VALUES ('dm', ?)`,
                        [me]
                    );
                    conversationId = insConv.insertId;

                    await conn.query(
                        `INSERT INTO conversation_members (conversation_id, user_id, role)
           VALUES (?, LEAST(?, ?), 'owner'), (?, GREATEST(?, ?), 'member')`,
                        [conversationId, a, b, conversationId, a, b]
                    );
                }

                // 2) บันทึกข้อความ
                const trimmed = text.trim();
                if (!trimmed) {
                    await conn.rollback();
                    conn.release();
                    return res.status(400).json({ success: false, message: "Empty message", statusCode: 400 });
                }

                const [insMsg] = await conn.query<any>(
                    `INSERT INTO messages (conversation_id, sender_id, body, kind)
         VALUES (?, ?, ?, 'text')`,
                    [conversationId, me, trimmed]
                );
                const messageId = insMsg.insertId;

                // 3) แนบไฟล์ (ถ้ามี) — attachments เป็น array ของ { type, storage_key, url, ... }
                if (Array.isArray(attachments) && attachments.length > 0) {
                    for (const f of attachments) {
                        await conn.query(
                            `INSERT INTO attachments
               (message_id, type, storage_provider, storage_key, url, file_name, mime_type, byte_size, width, height, duration_sec, checksum_sha256)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                            [
                                messageId,
                                f.type,                             // 'image' | 'audio' | 'video' | 'file'
                                f.storage_provider ?? 'local',
                                f.storage_key,
                                f.url ?? null,
                                f.file_name ?? null,
                                f.mime_type ?? null,
                                f.byte_size ?? null,
                                f.width ?? null,
                                f.height ?? null,
                                f.duration_sec ?? null,
                                f.checksum_sha256 ?? null,
                            ]
                        );
                    }
                }

                await conn.commit();
                conn.release();

                // 4) Trigger ไปยัง Pusher
                const payload = { from: user.username, text: trimmed, at: Date.now() };
                await pusher.trigger(room, "message", payload);

                return res.json({ success: true, message: "Message sent", statusCode: 200, data: { conversationId, messageId } });
            } catch (e) {
                try { await (conn as any)?.rollback(); } catch { }
                (conn as any)?.release?.();
                console.error("[sendChat] DB error:", e);
                return res.status(500).json({ success: false, message: "DB error", statusCode: 500 });
            }
        } else {
            // presence room (ห้องรวม) — ถ้าต้องการเก็บ ให้เตรียม conversation_id ล็อบบี้ไว้ก่อน
            const LOBBY_CONVERSATION_ID = Number(process.env.LOBBY_CONVERSATION_ID || 0);
            if (!LOBBY_CONVERSATION_ID) {
                // ถ้ายังไม่ได้เตรียม ให้ตอบเฉพาะ pusher ไปก่อน
                const payload = { from: user.username, text: text.trim(), at: Date.now() };
                await pusher.trigger(room, "message", payload);
                return res.json({ success: true, message: "Message sent (not stored)", statusCode: 200 });
            }

            // เก็บลงห้องรวม
            const trimmed = text.trim();
            if (!trimmed) {
                return res.status(400).json({ success: false, message: "Empty message", statusCode: 400 });
            }

            const [insMsg] = await pool.query<any>(
                `INSERT INTO messages (conversation_id, sender_id, body, kind)
       VALUES (?, ?, ?, 'text')`,
                [LOBBY_CONVERSATION_ID, user.id, trimmed]
            );

            const payload = { from: user.username, text: trimmed, at: Date.now() };
            await pusher.trigger(room, "message", payload);

            return res.json({ success: true, message: "Message sent", statusCode: 200, data: { conversationId: LOBBY_CONVERSATION_ID, messageId: insMsg.insertId } });
        }
    };
    //#endregion

    //#region getMessages
    getMessages = async (req: Request, res: Response<ApiResponse>) => {
        const me = (req.session as any).user as SessionUser | undefined;
        if (!me) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });

        const cid = Number((req.query as any).conversationId ?? 0);
        const limit = Math.min(Number((req.query as any).limit ?? 50), 100);   // cap 100
        const beforeId = Number((req.query as any).beforeId ?? 0);             // สำหรับ seek-pagination

        if (!cid) {
            return res.status(400).json({ success: false, message: "Bad request", statusCode: 400 });
        }

        // เช็ค membership
        const [mem] = await pool.query<any[]>(
            `SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1`,
            [cid, me.id]
        );
        if (mem.length === 0) {
            return res.status(403).json({ success: false, message: "Forbidden", statusCode: 403 });
        }

        // ใช้ seek-pagination: ดึงย้อนหลังก่อน message id ที่กำหนด
        const params: any[] = [cid];
        let cursorSql = "";
        if (beforeId > 0) {
            cursorSql = "AND m.id < ? ";
            params.push(beforeId);
        }

        params.push(limit);

        // รวม attachments เป็น JSON array ต่อข้อความ
        const [rows] = await pool.query<any[]>(
            `
    SELECT
      m.id,
      m.conversation_id,
      m.sender_id,
      m.body,
      m.kind,
      m.created_at,
      m.edited_at,
      COALESCE(
        JSON_ARRAYAGG(
          CASE WHEN a.id IS NULL THEN NULL ELSE
            JSON_OBJECT(
              'id', a.id,
              'type', a.type,
              'url', a.url,
              'file_name', a.file_name,
              'mime_type', a.mime_type,
              'byte_size', a.byte_size,
              'width', a.width,
              'height', a.height,
              'duration_sec', a.duration_sec
            )
          END
        ),
        JSON_ARRAY()
      ) AS attachments
    FROM messages m
    LEFT JOIN attachments a ON a.message_id = m.id
    WHERE m.conversation_id = ?
      AND m.deleted_at IS NULL
      ${cursorSql}
    GROUP BY m.id
    ORDER BY m.id DESC       -- ดึงย้อนหลัง (ล่าสุดก่อน)
    LIMIT ?
    `,
            params
        );

        // ให้ฝั่ง UI แสดงจากเก่า→ใหม่: reverse ที่นี่ให้เรียบง่าย
        const messages = rows.reverse();

        return res.json({
            success: true,
            data: { messages },
            message: "OK",
            statusCode: 200,
        });
    };
    //#endregion

    //#region resolveDM
    resolveDM = async (req: Request, res: Response<ApiResponse>) => {
        const me = (req.session as any).user as SessionUser | undefined;
        if (!me) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });

        const otherId = Number(req.query.otherId);
        if (!otherId) return res.status(400).json({ success: false, message: "Bad request", statusCode: 400 });

        const a = Math.min(me.id, otherId);
        const b = Math.max(me.id, otherId);

        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();

            const [found] = await conn.query<any[]>(
                `SELECT c.id
       FROM conversations c
       JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = ?
       JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = ?
       WHERE c.type = 'dm'
       LIMIT 1`,
                [a, b]
            );

            let conversationId: number;
            if (found.length > 0) {
                conversationId = found[0].id;
            } else {
                const [insConv] = await conn.query<any>(
                    `INSERT INTO conversations (type, created_by) VALUES ('dm', ?)`,
                    [me.id]
                );
                conversationId = insConv.insertId;
                await conn.query(
                    `INSERT INTO conversation_members (conversation_id, user_id, role)
         VALUES (?, ?, 'owner'), (?, ?, 'member')`,
                    [conversationId, a, conversationId, b]
                );
            }

            await conn.commit();
            return res.json({ success: true, message: "OK", statusCode: 200, data: { conversationId } });
        } catch (e) {
            await conn.rollback();
            console.error("[resolveDM] error:", e);
            return res.status(500).json({ success: false, message: "DB error", statusCode: 500 });
        } finally {
            conn.release();
        }
    };
    //#endregion

    //#region [List Users]
    listUsers = async (req: Request, res: Response<ApiResponse>) => {
        const me = (req.session as any).user as SessionUser | undefined;
        if (!me) {
            return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });
        }

        const [rows] = await pool.query<any[]>(
            `
    SELECT
      id,
      username,
      COALESCE(firstname, '') AS firstname,
      COALESCE(lastname, '')  AS lastname,
      TRIM(CONCAT(COALESCE(firstname, ''), ' ', COALESCE(lastname, ''))) AS fullname
    FROM accounts
    ORDER BY
      NULLIF(TRIM(COALESCE(firstname, '')), '') ASC,
      NULLIF(TRIM(COALESCE(lastname,  '')), '') ASC,
      id ASC
    `
        );

        return res.json({
            success: true,
            data: { users: rows as any[] },
            message: "OK",
            statusCode: 200,
        });
    };
    //#endregion
}