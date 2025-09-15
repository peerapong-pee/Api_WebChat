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

    //#region Chat Send
    sendChat = async (req: Request, res: Response<ApiResponse>) => {
        // ตรวจสอบสิทธิ์
        const user = (req.session as any).user as SessionUser | undefined;
        if (!user) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });

        const { room, text, attachments } = req.body ?? {};
        if (typeof room !== "string" || typeof text !== "string") {
            return res.status(400).json({ success: false, message: "Bad request", statusCode: 400 });
        }
        // ห้องรวม
        const isPresence = false
        // ห้องเดี่ยว
        const isDM = /^private-chat-\d+-\d+$/.test(room);
        if (!isDM) {
            return res.status(400).json({ success: false, message: "Invalid room", statusCode: 400 });
        }

        // การสนทนา
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

            // ตรวจสอบให้แน่ใจว่ามีการสนทนา DM อยู่
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

                const payload = {
                    from: user.username,
                    sender_id: user.id,      
                    text: trimmed,
                    at: Date.now(),
                };
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
    // getMessages (เวอร์ชันแก้ alias ซ้ำ)
    getMessages = async (req: Request, res: Response<ApiResponse>) => {
        const me = (req.session as any).user as SessionUser | undefined;
        if (!me) {
            return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });
        }

        const cid = Number((req.query as any).conversationId ?? 0);
        const limit = Math.min(Number((req.query as any).limit ?? 50), 100);
        const beforeId = Number((req.query as any).beforeId ?? 0);

        if (!cid) {
            return res.status(400).json({ success: false, message: "Bad request", statusCode: 400 });
        }

        // ตรวจ membership
        const [mem] = await pool.query<any[]>(
            `SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1`,
            [cid, me.id]
        );
        if (mem.length === 0) {
            return res.status(403).json({ success: false, message: "Forbidden", statusCode: 403 });
        }

        const params: any[] = [cid];
        let cursorSql = "";
        if (beforeId > 0) {
            cursorSql = "AND m.id < ? ";
            params.push(beforeId);
        }
        params.push(limit);

        // ใช้ alias ไม่ซ้ำ: u=accounts, att=attachments
        const [rows] = await pool.query<any[]>(
            `
    SELECT
      m.id,
      m.conversation_id,
      m.sender_id,
      u.username AS sender_username,
      m.body,
      m.kind,
      m.created_at,
      m.edited_at,
      COALESCE(
        JSON_ARRAYAGG(
          CASE WHEN att.id IS NULL THEN NULL ELSE
            JSON_OBJECT(
              'id', att.id,
              'type', att.type,
              'url', att.url,
              'file_name', att.file_name,
              'mime_type', att.mime_type,
              'byte_size', att.byte_size,
              'width', att.width,
              'height', att.height,
              'duration_sec', att.duration_sec
            )
          END
        ),
        JSON_ARRAY()
      ) AS attachments
    FROM messages m
    JOIN accounts u ON u.id = m.sender_id              -- << เปลี่ยนเป็น u
    LEFT JOIN attachments att ON att.message_id = m.id -- << เปลี่ยนเป็น att
    WHERE m.conversation_id = ?
      AND m.deleted_at IS NULL
      ${cursorSql}
    GROUP BY
      m.id, m.conversation_id, m.sender_id, u.username, m.body, m.kind, m.created_at, m.edited_at
    ORDER BY m.id DESC
    LIMIT ?
    `,
            params
        );

        // เรียงกลับเป็นเก่า→ใหม่ให้ UI
        const messages = rows.reverse();

        return res.json({
            success: true,
            data: { messages },
            message: "OK",
            statusCode: 200,
        });
    };

    //#endregion

    //#region getLastConversation
    getLastConversation = async (req: Request, res: Response<ApiResponse>) => {
        const me = (req.session as any).user as SessionUser | undefined;
        if (!me) {
            return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });
        }

        // หา “ห้องที่ผมเป็นสมาชิก” แล้วเรียงตามเวลาข้อความล่าสุด (ถ้าไม่มีข้อความใช้เวลาสร้างห้อง)
        // กรณี DM ดึง peerId (สมาชิกอีกคน)
        const [rows] = await pool.query<any[]>(
            `
  SELECT
    c.id AS conversationId,
    c.type AS type,
    COALESCE(MAX(m.created_at), c.created_at) AS last_at,
    (
      SELECT cm2.user_id FROM conversation_members cm2
      WHERE cm2.conversation_id = c.id AND cm2.user_id <> ?
      LIMIT 1
    ) AS peerId
  FROM conversations c
  JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = ?
  LEFT JOIN messages m ON m.conversation_id = c.id
  WHERE c.type = 'dm'                  -- << สำคัญ
  GROUP BY c.id
  ORDER BY last_at DESC
  LIMIT 1
  `,
            [me.id, me.id]
        );

        if (!rows || rows.length === 0) {
            return res.json({ success: true, statusCode: 200, message: "OK", data: null });
        }


        const r = rows[0];
        if (r.type === "dm" && r.peerId) {
            return res.json({
                success: true,
                statusCode: 200,
                message: "OK",
                data: { kind: "dm", peerId: Number(r.peerId), conversationId: Number(r.conversationId) }
            });
        }

        // type อื่น ๆ เช่น lobby / group
        return res.json({
            success: true,
            statusCode: 200,
            message: "OK",
            data: { kind: "lobby", conversationId: Number(r.conversationId) }
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

    //#region ListUsers
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
      COALESCE(lastname, '')  AS lastname
    FROM accounts
    ORDER BY
      NULLIF(TRIM(COALESCE(firstname, '')), '') ASC,
      NULLIF(TRIM(COALESCE(lastname,  '')), '')  ASC,
      id ASC
    `
        );

        return res.json({
            success: true,
            data: { users: rows },
            message: "OK",
            statusCode: 200,
        });
    };
    //#endregion

}