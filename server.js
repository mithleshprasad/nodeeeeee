// server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
const port = 4000;

app.use(cors({ origin: "http://localhost:3000" }));
console.log("ZOOM_SDK_KEY",process.env.ZOOM_SDK_KEY)
console.log(" process.env.ZOOM_SDK_SECRET", process.env.ZOOM_SDK_SECRET)
app.get("/signature", (req, res) => {
  try {
    const meetingNumber = req.query.meetingNumber;
    const role = req.query.role || 0; // 0 = attendee, 1 = host

    const iat = Math.floor(new Date().getTime() / 1000) - 30; // issue time
    const exp = iat + 60 * 60 * 2; // valid for 2 hours

    const header = { alg: "HS256", typ: "JWT" };
    const payload = {
      sdkKey: process.env.ZOOM_SDK_KEY,
      mn: meetingNumber,
      role: role,
      iat: iat,
      exp: exp,
      appKey: process.env.ZOOM_SDK_KEY,
      tokenExp: exp,
    };

    function base64url(source) {
      return Buffer.from(JSON.stringify(source))
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
    }

    const headerBase64 = base64url(header);
    const payloadBase64 = base64url(payload);
    const data = `${headerBase64}.${payloadBase64}`;

    const signature = crypto
      .createHmac("sha256", process.env.ZOOM_SDK_SECRET)
      .update(data)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    res.json({ signature: `${data}.${signature}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(port, () =>
  console.log(`✅ Zoom Signature server running on http://localhost:${port}`)
);
