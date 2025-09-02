import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { pool } from "../db";
import dotenv from "dotenv";
import { apiResponse } from "../model/Response/response_standard";

dotenv.config();
const secret = process.env.JWT_SECRET || "mysecretkey";

export default class SigninController {
  // ✅ Signin ด้วย accounts (email + ticket)
  async Signin(req: Request, res: Response<apiResponse>): Promise<Response<apiResponse>> {
    try {
      // รองรับทั้งรูปแบบเก่า (user/password) และใหม่ (email/ticket)
      const email = (req.body.email ?? req.body.user ?? "").toString().trim();
      const ticket = (req.body.ticket ?? req.body.password ?? "").toString();

      if (!email || !ticket) {
        return res.status(400).json({
          success: false,
          message: !email && !ticket
            ? "กรุณากรอกอีเมลและรหัสบัตร (ticket)"
            : !email
              ? "กรุณากรอกอีเมล"
              : "กรุณากรอกรหัสบัตร (ticket)",
          statusCode: 400,
        });
      }

      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailPattern.test(email)) {
        return res.status(400).json({
          success: false,
          message: "รูปแบบอีเมลไม่ถูกต้อง",
          statusCode: 400,
        });
      }

      // ✅ ใช้ accounts + เช็ค ticket ด้วย SHA2(?,512)
      const [rows] = await pool.query<any[]>(
        `SELECT id, username, email, fullname
           FROM accounts
          WHERE email = ?
            AND ticket = SHA2(?, 512)`,
        [email, ticket]
      );

      if (!Array.isArray(rows) || rows.length === 0) {
        return res.status(200).json({ success: false, message: "อีเมลหรือรหัสไม่ถูกต้อง", statusCode: 200 });
      }

      const u = rows[0];
      // สร้าง token (หากยังต้องใช้)
      const token = jwt.sign(
        { id: u.id, email: u.email, username: u.username, role: u.username === "admin" ? "admin" : "user" },
        secret,
        { expiresIn: "1h" }
      );

      // ถ้าใช้ session ในระบบแชท แนะนำเก็บไว้ด้วย
      (req.session as any).user = {
        id: u.id,
        email: u.email,
        username: u.username,
        fullname: u.fullname,
        isAdmin: u.username === "admin",
      };

      return res.status(200).json({
        success: true,
        message: "เข้าสู่ระบบสำเร็จ",
        data: {
          users_id: u.id,              // รักษา key ชื่อเดิมให้ client ไม่พัง
          token,
          firstname: u.fullname,       // ไม่มี firstname ใน accounts → map fullname
          total_credit: 0              // ไม่มีใน accounts → ให้ค่า 0/ตัดออกจาก type ถ้าแก้ได้
        },
        statusCode: 200,
      });

    } catch (error) {
      console.error(error);
      return res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดขณะเข้าสู่ระบบ", statusCode: 500 });
    }
  }
}
