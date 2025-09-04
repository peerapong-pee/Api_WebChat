import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { pool } from "../db";
import dotenv from "dotenv";
import { apiResponse } from "../model/Response/response_standard";

dotenv.config();
const secret = process.env.JWT_SECRET || "mysecretkey";

export default class SigninController {

  //#region Register
  async Register(req: Request, res: Response<apiResponse>): Promise<Response<apiResponse>> {
    try {
      const rawUsername = (req.body.username ?? "").toString().trim();
      const rawEmail = (req.body.email ?? "").toString().trim();
      const rawFullname = (req.body.fullname ?? "").toString().trim();
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
      const fullname = rawFullname || username;
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
        const errs = [];
        if (dupRow.email_dup > 0) errs.push("อีเมลนี้ถูกใช้งานแล้ว");
        if (dupRow.user_dup > 0) errs.push("username นี้ถูกใช้งานแล้ว");
        return res.status(409).json({
          success: false,
          message: errs.join(", "),
          statusCode: 409,
        });
      }

      const [result] = await pool.query<any>(
        `INSERT INTO accounts (username, email, fullname, ticket)
         VALUES (?, ?, ?, SHA2(?, 512))`,
        [username, email, fullname, ticket]
      );

      const newId = result.insertId as number;
      const token = jwt.sign(
        { id: newId, email, username, role: username === "admin" ? "admin" : "user" },
        secret,
        { expiresIn: "1h" }
      );

      (req.session as any).user = {
        id: newId,
        email,
        username,
        fullname,
        isAdmin: username === "admin",
      };

      return res.status(201).json({
        success: true,
        message: "สมัครสมาชิกสำเร็จ",
        data: {
          users_id: newId,
          token,
          firstname: fullname,
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
}
