const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");
const admin = require("firebase-admin");

const app = express();

app.use(cors());
app.use(express.json());

// Firebase Admin
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

const resend = new Resend(process.env.RESEND_API_KEY);

// تخزين OTP مؤقتًا
const otpStore = new Map();

// تخزين البريد بعد التحقق من OTP
const verifiedStore = new Map();

app.post("/api/send-otp", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "البريد الإلكتروني مطلوب",
      });
    }

    const otp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    otpStore.set(email, {
      otp: otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    // إذا طلب رمز جديد، نلغي حالة التحقق القديمة
    verifiedStore.delete(email);

    await resend.emails.send({
      from: "InvestX <onboarding@resend.dev>",
      to: email,
      subject: "رمز التحقق - InvestX",
      html: `
        <div style="font-family: Arial; direction: rtl; text-align: center;">
          <h2>InvestX 📈</h2>
          <p>رمز التحقق الخاص بك هو:</p>

          <div style="
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            margin: 20px;
          ">
            ${otp}
          </div>

          <p>صلاحية الرمز 5 دقائق.</p>
          <p>إذا لم تطلب هذا الرمز، يمكنك تجاهل هذه الرسالة.</p>
        </div>
      `,
    });

    return res.json({
      success: true,
      message: "تم إرسال رمز التحقق",
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "تعذر إرسال رمز التحقق",
    });
  }
});

app.post("/api/verify-otp", (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const otp = req.body.otp?.trim();

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "البريد والرمز مطلوبان",
      });
    }

    const saved = otpStore.get(email);

    if (!saved) {
      return res.status(400).json({
        success: false,
        message: "رمز التحقق غير موجود أو انتهت صلاحيته",
      });
    }

    if (Date.now() > saved.expiresAt) {
      otpStore.delete(email);

      return res.status(400).json({
        success: false,
        message: "انتهت صلاحية رمز التحقق",
      });
    }

    if (saved.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: "رمز التحقق غير صحيح",
      });
    }

    otpStore.delete(email);

    // السماح بتغيير كلمة المرور لمدة 10 دقائق
    verifiedStore.set(email, {
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    return res.json({
      success: true,
      message: "تم التحقق من الرمز بنجاح",
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "حدث خطأ أثناء التحقق",
    });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const newPassword = req.body.newPassword;

    if (!email || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "البريد وكلمة المرور مطلوبان",
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تكون 6 أحرف على الأقل",
      });
    }

    const verified = verifiedStore.get(email);

    if (!verified) {
      return res.status(403).json({
        success: false,
        message: "يجب التحقق من رمز OTP أولًا",
      });
    }

    if (Date.now() > verified.expiresAt) {
      verifiedStore.delete(email);

      return res.status(403).json({
        success: false,
        message: "انتهت صلاحية التحقق",
      });
    }

    // البحث عن المستخدم في Firebase
    const user = await admin.auth().getUserByEmail(email);

    // تغيير كلمة المرور
    await admin.auth().updateUser(user.uid, {
      password: newPassword,
    });

    // منع إعادة استخدام التحقق
    verifiedStore.delete(email);

    return res.json({
      success: true,
      message: "تم تغيير كلمة المرور بنجاح",
    });
  } catch (error) {
    console.error(error);

    if (error.code === "auth/user-not-found") {
      return res.status(404).json({
        success: false,
        message: "لا يوجد حساب بهذا البريد الإلكتروني",
      });
    }

    return res.status(500).json({
      success: false,
      message: "تعذر تغيير كلمة المرور",
    });
  }
});

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "InvestX OTP Backend is running",
  });
});

module.exports = app;