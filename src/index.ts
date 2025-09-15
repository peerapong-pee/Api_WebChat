import "dotenv/config";
import express from "express";
import session from "express-session";
import cors from "cors";
import path from "path";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mysql from "mysql2/promise";
import Routes from "./routes";
import { pusher } from "./pusher";

const MySQLStore = require("express-mysql-session")(session);

const app = express();

const requiredEnv = {
  DB_HOST: process.env.DB_HOST,
  DB_PORT: process.env.DB_PORT,
  DB_USER: process.env.DB_USER,
  DB_PASSWORD: process.env.DB_PASSWORD,
  DB_NAME: process.env.DB_NAME,
};
const missing = Object.entries(requiredEnv)
  .filter(([, v]) => v === undefined || v === null || v === "")
  .map(([k]) => k);
if (missing.length) {
  console.error("[ENV ERROR] Missing:", missing.join(", "));
  throw new Error("Database env is missing. Please check your .env");
}
console.log("[DB CONFIG]", {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  hasPassword: !!process.env.DB_PASSWORD,
  db: process.env.DB_NAME,
});

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));

app.use(cors({
  origin: ["http://localhost:3000"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);

const pool = mysql.createPool({
  host: process.env.DB_HOST!,
  port: Number(process.env.DB_PORT!),
  user: process.env.DB_USER!,
  password: process.env.DB_PASSWORD!,
  database: process.env.DB_NAME!,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

pool
  .query("SELECT 1")
  .then(() => console.log("[DB] Connection OK"))
  .catch((e) => console.error("[DB] Connection FAILED:", e?.message || e));

const sessionStore = new MySQLStore(
  {
    clearExpired: true,
    checkExpirationInterval: 15 * 60 * 1000,
    expiration: 24 * 60 * 60 * 1000,
  },
  pool
);

const isProd = process.env.NODE_ENV === "production";
app.use(session({
  secret: process.env.SESSION_SECRET || "dev_secret",
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    sameSite: isProd ? "none" : "lax",
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

const loginLimiter = rateLimit({
  windowMs: 60_000,
  max: 7,
  standardHeaders: true,
  legacyHeaders: false,
});

const pusherAuthLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(Routes);
app.use("/pusher/auth", pusherAuthLimiter);

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

app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => {
  console.log("API running on http://localhost:" + PORT);
});
