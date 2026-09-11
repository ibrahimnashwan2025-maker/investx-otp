const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");

const app = express();

app.use(cors());
app.use(express.json());

const resend = new Resend(process.env.RESEND_API_KEY);

// تخزين مؤقت للرموز أثناء التجربة
const otpStore = new Map();

app.post("/api/send-otp", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "البريد الإلكتروني مطلوب",
      });
    }

    // إنشاء رمز من 6 أرقام
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // صلاحية الرمز 5 دقائق
    const expiresAt = Date.now() + 5 * 60 * 1000;

    otpStore.set(email, {
      otp,
      expiresAt,
    });

    const { data, error } = await resend.emails.send({
      from: "InvestX <onboarding@resend.dev>",
      to: [email],
      subject: "رمز استعادة كلمة المرور - InvestX",
      html: `
        <div style="font-family: Arial; direction: rtl; text-align: center;">
          <h2>InvestX 📈</h2>

          <p>رمز التحقق الخاص بك لاستعادة كلمة المرور:</p>

          <div style="
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            margin: 25px;
          ">
            ${otp}
          </div>

          <p>صلاحية الرمز 5 دقائق.</p>

          <p>إذا لم تطلب استعادة كلمة المرور، تجاهل هذه الرسالة.</p>
        </div>
      `,
    });

    if (error) {
      console.error("Resend error:", error);

      otpStore.delete(email);

      return res.status(500).json({
        success: false,
        message: "تعذر إرسال رمز التحقق",
      });
    }

    console.log(`OTP sent to ${email}: ${otp}`);

    return res.json({
      success: true,
      message: "تم إرسال رمز التحقق",
    });
  } catch (error) {
    console.error("Server error:", error);

    return res.status(500).json({
      success: false,
      message: "حدث خطأ في الخادم",
    });
  }
});

app.post("/api/verify-otp", (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const otp = String(req.body.otp || "").trim();

    const record = otpStore.get(email);

    if (!record) {
      return res.status(400).json({
        success: false,
        message: "لا يوجد رمز تحقق. اطلب رمزًا جديدًا.",
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(email);

      return res.status(400).json({
        success: false,
        message: "انتهت صلاحية رمز التحقق.",
      });
    }

    if (otp !== record.otp) {
      return res.status(400).json({
        success: false,
        message: "رمز التحقق غير صحيح.",
      });
    }

    otpStore.delete(email);

    return res.json({
      success: true,
      message: "تم التحقق من الرمز",
    });
  } catch (error) {
    console.error("Verify error:", error);

    return res.status(500).json({
      success: false,
      message: "حدث خطأ في التحقق",
    });
  }
});

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "InvestX OTP Backend is running 🚀",
  });
});

module.exports = app;