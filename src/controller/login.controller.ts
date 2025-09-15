import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { pool } from "../db";
import dotenv from "dotenv";
import { ApiResponse } from "../model/Response/response_standard";
import type { SessionUser } from "../types";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";

dotenv.config();
const secret = process.env.JWT_SECRET || "mysecretkey";

export default class logininController {

  //#region LOGIN
  login = async (req: Request, res: Response<ApiResponse>) => {
    const { email, password } = (req.body ?? {}) as { email?: string; password?: string };
    const userEmail = (email ?? "").trim().toLowerCase();
    const plain = (password ?? "").toString();

    if (!userEmail || !plain) {
      return res.status(400).json({ success: false, message: "Missing email or password", statusCode: 400 });
    }

    try {
      // ใช้ TRIM/LOWER ทั้งฝั่ง SQL เพื่อกันช่องว่าง/เคส
      const [rows] = await pool.query<any[]>(
        "SELECT id, username, email, firstname, lastname, password FROM accounts WHERE TRIM(LOWER(email)) = ? LIMIT 1",
        [userEmail]
      );

      if (!Array.isArray(rows) || rows.length !== 1) {
        console.warn("[LOGIN] no row found for email:", userEmail);
        return res.status(401).json({ success: false, message: "Invalid credentials", statusCode: 401 });
      }

      const row = rows[0];

      const ok = !!row.password && (await bcrypt.compare(plain, row.password));

      if (!ok) {
        return res.status(401).json({ success: false, message: "Invalid credentials", statusCode: 401 });
      }

      const u: SessionUser = {
        id: row.id,
        email: row.email,
        username: row.username,
        firstname: row.firstname,
        lastname: row.lastname,
        isAdmin: row.username === "admin",
      };

      req.session.regenerate((regenErr) => {
        if (regenErr) {
          console.error("[LOGIN] session regenerate error:", regenErr);
          return res.status(500).json({ success: false, message: "Session error", statusCode: 500 });
        }
        (req.session as any).user = u;
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error("[LOGIN] session save error:", saveErr);
            return res.status(500).json({ success: false, message: "Session save error", statusCode: 500 });
          }
          return res.status(200).json({ success: true, message: "OK", statusCode: 200, data: { user: u } });
        });
      });
    } catch (e) {
      console.error("LOGIN error:", e);
      return res.status(500).json({ success: false, message: "Internal error", statusCode: 500 });
    }
  };
  //#endregion

  //#region Register
  async Register(req: Request, res: Response<ApiResponse>): Promise<Response<ApiResponse>> {
    try {
      const rawUsername = (req.body.username ?? "").toString().trim();
      const rawEmail = (req.body.email ?? "").toString().trim();
      const rawFisstname = (req.body.firstname ?? "").toString().trim();
      const rawLastname = (req.body.lastname ?? "").toString().trim();
      const rawTicket = (req.body.ticket ?? req.body.password ?? "").toString();

      if (!rawUsername || !rawEmail || !rawTicket) {
        const missing = [
          !rawUsername ? "username" : null,
          !rawEmail ? "email" : null,
          !rawTicket ? "ticket" : null,
        ].filter(Boolean).join(", ");
        return res.status(400).json({
          success: false,
          message: `กรุณากรอกข้อมูลให้ครบถ้วน: ${missing}`,
          statusCode: 400,
        });
      }

      const username = rawUsername.toLowerCase();
      const email = rawEmail.toLowerCase();
      const firstname = rawFisstname;
      const lastname = rawLastname;
      const ticket = rawTicket;

      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email)) {
        return res.status(400).json({
          success: false,
          message: "รูปแบบอีเมลไม่ถูกต้อง",
          statusCode: 400,
        });
      }

      const usernamePattern = /^[a-z0-9_]{3,24}$/;
      if (!usernamePattern.test(username)) {
        return res.status(400).json({
          success: false,
          message: "username ต้องเป็น a-z, 0-9, _ และยาว 3–24 ตัวอักษร",
          statusCode: 400,
        });
      }

      const [dup] = await pool.query<any[]>(
        `SELECT 
            SUM(CASE WHEN email = ? THEN 1 ELSE 0 END) AS email_dup,
            SUM(CASE WHEN username = ? THEN 1 ELSE 0 END) AS user_dup
         FROM accounts
         WHERE email = ? OR username = ?`,
        [email, username, email, username]
      );
      const dupRow = Array.isArray(dup) && dup[0] ? dup[0] : { email_dup: 0, user_dup: 0 };
      if (dupRow.email_dup > 0 || dupRow.user_dup > 0) {
        const errs: string[] = [];
        if (dupRow.email_dup > 0) errs.push("อีเมลนี้ถูกใช้งานแล้ว");
        if (dupRow.user_dup > 0) errs.push("username นี้ถูกใช้งานแล้ว");
        return res.status(409).json({
          success: false,
          message: errs.join(", "),
          statusCode: 409,
        });
      }

      const hashed = await bcrypt.hash(ticket, 10);

      const [result] = await pool.query<any>(
        `INSERT INTO accounts (username, email, firstname, lastname, password)
         VALUES (?, ?, ?, ?, ?)`,
        [username, email, firstname, lastname, hashed]
      );

      const newId = (result as any).insertId as number;
      const token = jwt.sign(
        { id: newId, email, username, role: username === "admin" ? "admin" : "user" },
        secret,
        { expiresIn: "1h" }
      );

      (req.session as any).user = {
        id: newId,
        email,
        username,
        firstname,
        lastname,
        isAdmin: username === "admin",
      };

      return res.status(201).json({
        success: true,
        message: "สมัครสมาชิกสำเร็จ",
        data: {
          id: newId,
          token,
          firstname,
          lastname,
        },
        statusCode: 201,
      });

    } catch (err: any) {
      if (err && err.code === "ER_DUP_ENTRY") {
        const msg = /for key '.*email.*/i.test(err.sqlMessage || "")
          ? "อีเมลนี้ถูกใช้งานแล้ว"
          : /for key '.*username.*/i.test(err.sqlMessage || "")
            ? "username นี้ถูกใช้งานแล้ว"
            : "ข้อมูลซ้ำกับที่มีอยู่แล้ว";
        return res.status(409).json({ success: false, message: msg, statusCode: 409 });
      }

      console.error(err);
      return res.status(500).json({
        success: false,
        message: "เกิดข้อผิดพลาดขณะสมัครสมาชิก",
        statusCode: 500,
      });
    }
  }
  //#endregion

  //#region ME
  me = (req: Request, res: Response<ApiResponse>) => {
    const user = (req.session as any).user as SessionUser | undefined;
    if (!user) return res.status(401).json({ success: false, message: "Not authenticated", statusCode: 401 });
    return res.status(200).json({ success: true, user, message: "OK", statusCode: 200 });
  };
  //#endregion

  //#region ForgotPassword
  ForgotPassword = async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { email } = req.body as { email?: string };

      if (!email) {
        return res
          .status(400)
          .json({ success: false, message: "กรุณากรอกอีเมล", statusCode: 400 });
      }

      // ✅ ใช้ accounts + id
      const [rows] = await pool.query<any[]>(
        "SELECT id, email, firstname FROM accounts WHERE email = ? LIMIT 1",
        [email]
      );

      if (!rows || rows.length === 0) {
        // จะตอบ success เพื่อลด user enumeration ก็ได้ แต่ตามเดิมของคุณ:
        return res
          .status(200)
          .json({ success: false, message: "ไม่พบผู้ใช้งานนี้", statusCode: 200 });
      }

      const user = rows[0];
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetLink = `${process.env.FRONTEND_URL}/signin_signout/reset-password?token=${resetToken}`;

      await pool.query(
        "UPDATE accounts SET reset_token = ?, reset_token_expire = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?",
        [resetToken, user.id]
      );

      const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
          user: process.env.MAIL_USER,
          pass: process.env.MAIL_PASS, // ต้องเป็น App Password
        },
      });

      await transporter.sendMail({
        from: `"MBT WebChat" <${process.env.MAIL_USER}>`,
        to: email,
        subject: "รีเซ็ตรหัสผ่าน - MBT",
        html: `
        <p>คุณได้ส่งคำขอรีเซ็ตรหัสผ่าน</p>
        <p>กรุณาคลิกลิงก์ด้านล่างเพื่อดำเนินการ (ลิงก์หมดอายุใน 1 ชั่วโมง):</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>หากคุณไม่ได้ทำรายการนี้ กรุณาเพิกเฉยอีเมลฉบับนี้</p>
      `,
      });

      return res
        .status(200)
        .json({ success: true, message: "📧 ส่งลิงก์รีเซ็ตรหัสผ่านไปยังอีเมลเรียบร้อยแล้ว", statusCode: 200 });

    } catch (error: any) {
      console.error("ForgotPassword error:", error?.message || error);
      return res
        .status(500)
        .json({ success: false, message: "เกิดข้อผิดพลาดในการส่งอีเมล", statusCode: 500 });
    }
  };
  //#endregion

  //#region ResetPassword
  ResetPassword = async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { token, password } = req.body as { token?: string; password?: string };

      if (!token || !password) {
        return res
          .status(400)
          .json({ success: false, message: "ข้อมูลไม่ครบถ้วน", statusCode: 400 });
      }

      const [rows] = await pool.query<any[]>(
        "SELECT id FROM accounts WHERE reset_token = ? AND reset_token_expire > NOW() LIMIT 1",
        [token]
      );

      if (rows.length === 0) {
        return res
          .status(200)
          .json({ success: false, message: "ลิงก์ไม่ถูกต้องหรือหมดอายุแล้ว", statusCode: 200 });
      }

      const userId = rows[0].id;
      const hashedPassword = await bcrypt.hash(password, 10);

      await pool.query(
        "UPDATE accounts SET password = ?, reset_token = NULL, reset_token_expire = NULL WHERE id = ?",
        [hashedPassword, userId]
      );

      return res
        .status(200)
        .json({ success: true, message: "เปลี่ยนรหัสผ่านเรียบร้อยแล้ว", statusCode: 200 });
    } catch (err) {
      console.error("ResetPassword error:", err);
      return res
        .status(500)
        .json({ success: false, message: "เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน", statusCode: 500 });
    }
  };
  //#endregion

  //#region VerifyResetToken
  VerifyResetToken = async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { token } = req.params as { token?: string };
      if (!token) {
        return res
          .status(400)
          .json({ success: false, message: "ไม่พบ token", statusCode: 400 });
      }

      const [rows] = await pool.query<any[]>(
        "SELECT id FROM accounts WHERE reset_token = ? AND reset_token_expire > NOW() LIMIT 1",
        [token]
      );

      if (rows.length === 0) {
        return res
          .status(200)
          .json({ success: false, message: "ลิงก์ไม่ถูกต้องหรือหมดอายุแล้ว", statusCode: 200 });
      }

      return res
        .status(200)
        .json({ success: true, message: "ลิงก์ใช้งานได้", statusCode: 200 });
    } catch (error) {
      console.error("VerifyResetToken error:", error);
      return res
        .status(500)
        .json({ success: false, message: "ตรวจสอบลิงก์ล้มเหลว", statusCode: 500 });
    }
  };
  //#endregion

  //#region LOGOUT
  logout = (req: Request, res: Response<ApiResponse>) => {
    req.session.destroy(() => res.json({ success: true, message: "OK", statusCode: 200 }));
  };
  //#endregion

}
