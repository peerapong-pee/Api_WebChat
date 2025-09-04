// src/auth.ts
import { Router } from "express";
import { pool } from "./db";
import { sha512 } from "js-sha512";
import { pusher } from "./pusher";
import type { SessionUser } from "./types";

const router = Router();

router.post("/login", async (req, res) => {
  const { email, ticket } = req.body ?? {};
  if (!email || !ticket) {
    return res.status(400).json({ ok: false, message: "Missing email or ticket" });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, username, email, fullname, ticket FROM accounts WHERE email=? AND ticket=?",
      [email, sha512(ticket)]
    );
    const list = rows as any[];
    if (list.length !== 1) {
      return res.status(401).json({ ok: false, message: "Invalid credentials" });
    }

    const u: SessionUser = {
      id: list[0].id,
      email: list[0].email,
      username: list[0].username,
      fullname: list[0].fullname,
      isAdmin: list[0].username === "admin",
    };

    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error("session regenerate error:", regenErr);
        return res.status(500).json({ ok: false, message: "Session error" });
      }
      (req.session as any).user = u;
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("session save error:", saveErr);
          return res.status(500).json({ ok: false, message: "Session save error" });
        }
        res.json({ ok: true, user: u });
      });
    });
  } catch (e) {
    console.error("LOGIN error:", e);
    res.status(500).json({ ok: false, message: "Internal error" });
  }
});

router.get("/me", (req, res) => {
  const user = (req.session as any).user as SessionUser | undefined;
  if (!user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user });
});

router.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

router.post("/pusher/auth", (req, res) => {
  const user = (req.session as any).user;
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
  res.send(auth);
});

router.post("/api/chat/send", async (req, res) => {
  const user = (req.session as any).user;
  if (!user) return res.status(401).json({ ok: false, message: "Not authenticated" });

  const { room, text } = req.body ?? {};
  if (typeof room !== "string" || typeof text !== "string") {
    return res.status(400).json({ ok: false, message: "Bad request" });
  }

  const isPresence = /^presence-[A-Za-z0-9_\-:.=,]+$/.test(room);
  const isDM = /^private-chat-\d+-\d+$/.test(room);
  if (!isPresence && !isDM) return res.status(400).json({ ok: false, message: "Invalid room" });

  if (isDM) {
    const [, , aStr, bStr] = room.split("-");
    const a = Number(aStr), b = Number(bStr), me = Number(user.id);
    if (me !== a && me !== b) return res.status(403).json({ ok: false, message: "Forbidden" });
  }

  const payload = { from: user.username, text: text.trim(), at: Date.now() };
  await pusher.trigger(room, "message", payload);

  res.json({ ok: true });
});

router.get("/users", async (req, res) => {
  const me = (req.session as any).user as SessionUser | undefined;
  if (!me) return res.status(401).json({ ok: false });

  const [rows] = await pool.query(
    "SELECT id, username, fullname FROM accounts ORDER BY fullname ASC"
  );
  res.json({ ok: true, users: rows });
});

export default router;
