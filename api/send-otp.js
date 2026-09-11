const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");

const app = express();

app.use(cors());
app.use(express.json());

const otpStore = new Map();
const verifiedStore = new Map();

const resend = new Resend(process.env.RESEND_API_KEY);

// الصفحة الرئيسية
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "InvestX OTP Backend is running",
  });
});

// إرسال OTP
app.post("/api/send-otp", async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();

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
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    verifiedStore.delete(email);

    await resend.emails.send({
      from: "InvestX <onboarding@resend.dev>",
      to: email,
      subject: "رمز التحقق - InvestX",
      html: `
        <div style="font-family:Arial;direction:rtl;text-align:center">
          <h2>InvestX 📈</h2>
          <p>رمز التحقق الخاص بك هو:</p>
          <div style="
            font-size:32px;
            font-weight:bold;
            letter-spacing:8px;
            margin:20px
          ">
            ${otp}
          </div>
          <p>صلاحية الرمز 5 دقائق.</p>
          <p>إذا لم تطلب هذا الرمز، يمكنك تجاهل هذه الرسالة.</p>
        </div>
      `,
    });

    res.json({
      success: true,
      message: "تم إرسال رمز التحقق",
    });
  } catch (error) {
    console.error("SEND OTP ERROR:", error);

    res.status(500).json({
      success: false,
      message: "تعذر إرسال رمز التحقق",
    });
  }
});

// التحقق من OTP
app.post("/api/verify-otp", (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();
    const otp = req.body?.otp?.trim();

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

    verifiedStore.set(email, {
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    res.json({
      success: true,
      message: "تم التحقق من الرمز بنجاح",
    });
  } catch (error) {
    console.error("VERIFY OTP ERROR:", error);

    res.status(500).json({
      success: false,
      message: "حدث خطأ أثناء التحقق",
    });
  }
});

// تغيير كلمة المرور
app.post("/api/reset-password", async (req, res) => {
  try {
    const email = req.body?.email?.trim().toLowerCase();
    const newPassword = req.body?.newPassword;

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

    // Firebase Admin يتم تحميله هنا فقط
    const admin = require("firebase-admin");

    if (!admin.apps.length) {
      const privateKey =
        process.env.FIREBASE_PRIVATE_KEY;

      if (
        !process.env.FIREBASE_PROJECT_ID ||
        !process.env.FIREBASE_CLIENT_EMAIL ||
        !privateKey
      ) {
        throw new Error(
          "Firebase environment variables are missing"
        );
      }

      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: privateKey.replace(/\\n/g, "\n"),
        }),
      });
    }

    const user =
      await admin.auth().getUserByEmail(email);

    await admin.auth().updateUser(user.uid, {
      password: newPassword,
    });

    verifiedStore.delete(email);

    res.json({
      success: true,
      message: "تم تغيير كلمة المرور بنجاح",
    });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);

    if (error.code === "auth/user-not-found") {
      return res.status(404).json({
        success: false,
        message: "لا يوجد حساب بهذا البريد الإلكتروني",
      });
    }

    res.status(500).json({
      success: false,
      message: "تعذر تغيير كلمة المرور",
    });
  }
});

module.exports = app;