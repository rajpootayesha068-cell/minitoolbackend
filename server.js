// @ts-nocheck
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const OpenAI = require("openai");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const path = require("path");

const app = express();

// =====================
// ENV VARIABLES
// =====================
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  "http://localhost:3000/auth/google/callback";

// =====================
// MIDDLEWARE
// =====================
app.use(
  cors({
    origin: true, // allows all origins (safe for development)
    credentials: true,
  })
);

app.use(bodyParser.json());

// Serve Static Frontend Files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// =====================
// SESSION CONFIGURATION
// =====================
app.use(
  session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,     // Set to true only in production with HTTPS
      sameSite: "lax",
    },
  })
);

// =====================
// IN-MEMORY USER DATABASE (Temporary)
// =====================
const userDatabase = [];

// =====================
// OPENAI CONFIGURATION
// =====================
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// =====================
// ROOT ROUTE - Serve Frontend
// =====================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// =====================
// HEALTH CHECK
// =====================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    openai: !!process.env.OPENAI_API_KEY,
  });
});

// =====================
// AUTH: SIGNUP
// =====================
app.post("/signup", async (req, res) => {
  const { email, password, fullName } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  const exists = userDatabase.find((u) => u.email === email);
  if (exists) {
    return res.status(400).json({ error: "User already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const user = {
    email,
    passwordHash,
    fullName: fullName || email.split("@")[0],
    plan: "free",
    authMethod: "email",
    createdAt: new Date(),
  };

  userDatabase.push(user);

  const token = jwt.sign(
    { email: user.email, plan: user.plan, fullName: user.fullName },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    success: true,
    message: "Signup successful",
    user: { email: user.email, fullName: user.fullName },
    token,
  });
});

// =====================
// AUTH: LOGIN
// =====================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = userDatabase.find((u) => u.email === email);
  if (!user) {
    return res.status(400).json({ error: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(400).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { email: user.email, plan: user.plan, fullName: user.fullName },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    success: true,
    message: "Login successful",
    user: { email: user.email, fullName: user.fullName },
    token,
  });
});

// =====================
// LOGOUT
// =====================
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: "Logged out" });
  });
});

// =====================
// GOOGLE OAUTH REDIRECT
// =====================
app.get("/auth/google", (req, res) => {
  const url =
    `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}` +
    `&response_type=code&scope=email profile&access_type=offline&prompt=consent`;

  res.redirect(url);
});

// =====================
// GOOGLE CALLBACK
// =====================
app.get("/auth/google/callback", async (req, res) => {
  try {
    const { code } = req.query;

    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      }
    );

    const access_token = tokenResponse.data.access_token;

    const userInfo = await axios.get(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: { Authorization: `Bearer ${access_token}` },
      }
    );

    const { email, name, picture, sub } = userInfo.data;

    let user = userDatabase.find((u) => u.email === email);

    if (!user) {
      user = {
        email,
        fullName: name,
        profilePic: picture,
        googleId: sub,
        authMethod: "google",
        plan: "free",
        createdAt: new Date(),
      };
      userDatabase.push(user);
    }

    const token = jwt.sign(
      { email: user.email, plan: user.plan, fullName: user.fullName },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // ⚠️ CHANGE THIS IN PRODUCTION (Vercel)
    res.redirect(`http://localhost:5500/profile.html?token=${token}`);
  } catch (err) {
    console.error(err);
    res.redirect("http://localhost:5500/login?error=auth_failed");
  }
});

// =====================
// PARAPHRASE
// =====================
app.post("/paraphrase", async (req, res) => {
  const { text, mode } = req.body;

  if (!text) return res.status(400).json({ error: "Text required" });

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    temperature: 0.8,
    messages: [
      {
        role: "system",
        content: "Rewrite text with meaning preserved but different structure.",
      },
      { role: "user", content: text },
    ],
  });

  res.json({
    success: true,
    paraphrased: response.choices[0].message.content.trim(),
  });
});

// =====================
// PLAGIARISM CHECK
// =====================
app.post("/plagiarism", async (req, res) => {
  const { text, sensitivity } = req.body;

  if (!text) return res.status(400).json({ error: "Text required" });

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    temperature: 0.3,
    messages: [
      {
        role: "system",
        content:
          "Return ONLY JSON: plagiarismScore, originalityScore, similarityScore.",
      },
      { role: "user", content: text },
    ],
  });

  res.json({
    success: true,
    result: response.choices[0].message.content,
  });
});

// =====================
// LOCAL SERVER START (Development Only)
// =====================
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
  });
}

// =====================
// VERCEL EXPORT (For Production)
// =====================
module.exports = app;