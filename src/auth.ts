import { Router } from "express";
import { pool } from "./db";
import { sha512 } from "js-sha512";
import { pusher } from "./pusher";
import type { SessionUser } from "./types";

const router = Router();

// POST /login  (email + ticket)
router.post("/login", async (req, res) => {
  const { email, ticket } = req.body ?? {};
  if (!email || !ticket) {
    return res.status(400).json({ ok: false, message: "Missing email or ticket" });
  }

  const [rows] = await pool.query(
    "SELECT id, username, email, fullname, ticket FROM accounts WHERE email=? AND ticket=?",
    [email, sha512(ticket)]
  );
  const list = rows as Array<any>;
  if (list.length === 1) {
    const u: SessionUser = {
      id: list[0].id,
      email: list[0].email,
      username: list[0].username,
      fullname: list[0].fullname,
      isAdmin: list[0].username === "admin",
    };
    (req.session as any).user = u;
    return res.json({ ok: true, user: u });
  }
  return res.status(401).json({ ok: false, message: "Invalid credentials" });
});

// GET /me
router.get("/me", (req, res) => {
  const user = (req.session as any).user as SessionUser | undefined;
  if (!user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user });
});

// POST /logout
router.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// POST /pusher/auth  (authorize presence/private channels)
router.post("/pusher/auth", (req, res) => {
  const user = (req.session as any).user as SessionUser | undefined;
  if (!user) return res.status(401).send("Not authenticated");

  const { channel_name, socket_id } = req.body ?? {};
  if (!channel_name || !socket_id) return res.status(400).send("Bad request");

  // presence channel ต้องคืน user_info ด้วย
  const presenceData = {
    user_id: String(user.id),                // ต้อง unique ต่อ user
    user_info: {
      username: user.username,
      fullname: user.fullname,
      isAdmin: user.isAdmin,
    },
  };

  const auth = pusher.authorizeChannel(socket_id, channel_name, presenceData);
  res.send(auth);
});

export default router;
