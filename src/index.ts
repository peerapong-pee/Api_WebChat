import "dotenv/config";
import express from "express";
import session from "express-session";
import cors from "cors";
import path from "path";

import authRoutes from "./auth";
import Routes from "./routes";
import { pusher } from "./pusher";

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || "dev_secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true },
}));

// Auth / Presence / Pusher auth
app.use(authRoutes);

// รวม API อื่น ๆ ที่เคยอยู่ใน server.ts
app.use("/api", Routes);

// ตัวอย่าง broadcast (เฉพาะ admin)
app.post("/api/broadcast", async (req, res) => {
  const user = (req.session as any).user;
  if (!user?.isAdmin) return res.status(403).json({ ok: false });

  const { text } = req.body ?? {};
  await pusher.trigger("presence-event-1", "server-announcement", {
    text,
    at: Date.now(),
  });
  res.json({ ok: true });
});

// static (optional)
app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log("API running on http://localhost:" + PORT);
});
