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

// =====================
// FIREBASE ADMIN INIT
// =====================
const admin = require("firebase-admin");

if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}
const db = admin.firestore();

// =====================
// STRIPE INIT
// =====================
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();

// =====================
// ENV VARIABLES
// =====================
const JWT_SECRET = process.env.JWT_SECRET || "";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  "http://localhost:3000/auth/google/callback";

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5500";
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

// =====================
// STRIPE PRICE IDs
// =====================
const PRICE_IDS = {
  premium_monthly: process.env.STRIPE_PRICE_MONTHLY, // price_xxx
  premium_yearly: process.env.STRIPE_PRICE_YEARLY,   // price_xxx
};

// =====================
// WEBHOOK ROUTE — must come BEFORE bodyParser.json()
// Raw body chahiye Stripe ko signature verify karne ke liye
// =====================
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, WEBHOOK_SECRET);
    } catch (err) {
      console.error("❌ Webhook signature failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // =====================
    // PAYMENT SUCCESS
    // =====================
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.metadata?.userId;
      const userEmail = session.metadata?.userEmail;
      const planKey = session.metadata?.planKey;
      const collection = session.metadata?.collection || "users";

      if (!userId) {
        console.warn("⚠️ No userId in metadata");
        return res.json({ received: true });
      }

      try {
        // Plan expiry calculate karo
        const now = new Date();
        let expiryDate = new Date(now);
        if (planKey === "premium_yearly") {
          expiryDate.setFullYear(expiryDate.getFullYear() + 1);
        } else {
          expiryDate.setMonth(expiryDate.getMonth() + 1);
        }

        // User plan update karo
        await db.collection(collection).doc(userId).set(
          {
            plan: "premium",
            planKey: planKey,
            stripeCustomerId: session.customer,
            stripeSubscriptionId: session.subscription,
            planStartDate: now.toISOString(),
            planExpiryDate: expiryDate.toISOString(),
            updatedAt: now.toISOString(),
          },
          { merge: true }
        );

        // Payment history save karo
        const paymentRecord = {
          sessionId: session.id,
          stripeCustomerId: session.customer,
          stripeSubscriptionId: session.subscription,
          planKey: planKey,
          amount: session.amount_total / 100, // cents to dollars
          currency: session.currency?.toUpperCase() || "USD",
          status: "paid",
          paymentDate: now.toISOString(),
          userEmail: userEmail || "",
          invoiceUrl: session.invoice || null,
        };

        // Sub-collection: users/{uid}/payment_history/{sessionId}
        await db
          .collection(collection)
          .doc(userId)
          .collection("payment_history")
          .doc(session.id)
          .set(paymentRecord);

        console.log(`✅ Plan upgraded to premium for user: ${userId}`);
        console.log(`✅ Payment history saved: ${session.id}`);
      } catch (err) {
        console.error("❌ Firebase update failed:", err.message);
      }
    }

    // =====================
    // SUBSCRIPTION CANCELLED
    // =====================
    if (event.type === "customer.subscription.deleted") {
      const subscription = event.data.object;
      const customerId = subscription.customer;

      try {
        // Customer ID se user dhundho
        const usersSnap = await db
          .collection("users")
          .where("stripeCustomerId", "==", customerId)
          .limit(1)
          .get();

        const googleSnap = await db
          .collection("google_users")
          .where("stripeCustomerId", "==", customerId)
          .limit(1)
          .get();

        const snap = !usersSnap.empty ? usersSnap : googleSnap;
        const collection = !usersSnap.empty ? "users" : "google_users";

        if (!snap.empty) {
          const userDoc = snap.docs[0];
          await db.collection(collection).doc(userDoc.id).set(
            {
              plan: "free",
              stripeSubscriptionId: null,
              planCancelledAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
            { merge: true }
          );
          console.log(`✅ Subscription cancelled for customer: ${customerId}`);
        }
      } catch (err) {
        console.error("❌ Cancel subscription update failed:", err.message);
      }
    }

    res.json({ received: true });
  }
);

// =====================
// MIDDLEWARE
// =====================
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// =====================
// SESSION
// =====================
app.use(
  session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      sameSite: "lax",
    },
  })
);

// =====================
// IN-MEMORY (existing — unchanged)
// =====================
const userDatabase = [];

// =====================
// OPENAI
// =====================
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// =====================
// ROOT
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
    stripe: !!process.env.STRIPE_SECRET_KEY,
    firebase: admin.apps.length > 0,
  });
});

// =====================
// AUTH: SIGNUP
// =====================
app.post("/signup", async (req, res) => {
  const { email, password, fullName } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const exists = userDatabase.find((u) => u.email === email);
  if (exists) return res.status(400).json({ error: "User already exists" });

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
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(400).json({ error: "Invalid credentials" });

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
// GOOGLE OAUTH
// =====================
app.get("/auth/google", (req, res) => {
  const url =
    `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}` +
    `&response_type=code&scope=email profile&access_type=offline&prompt=consent`;
  res.redirect(url);
});

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
      { headers: { Authorization: `Bearer ${access_token}` } }
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
    res.redirect(`${FRONTEND_URL}/profile.html?token=${token}`);
  } catch (err) {
    console.error(err);
    res.redirect(`${FRONTEND_URL}/login?error=auth_failed`);
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
// PLAGIARISM
// =====================
app.post("/plagiarism", async (req, res) => {
  const { text } = req.body;
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
  res.json({ success: true, result: response.choices[0].message.content });
});

// ============================================================
// ✅ STRIPE: CREATE CHECKOUT SESSION
// ============================================================
app.post("/create-checkout", async (req, res) => {
  const { planKey, userId, userEmail, collection } = req.body;

  if (!planKey || !userId || !userEmail) {
    return res.status(400).json({ error: "planKey, userId, userEmail required" });
  }

  const priceId = PRICE_IDS[planKey];
  if (!priceId) {
    return res.status(400).json({ error: `Invalid planKey: ${planKey}` });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      customer_email: userEmail,
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: {
        userId,
        userEmail,
        planKey,
        collection: collection || "users", // google_users ya users
      },
      success_url: `${FRONTEND_URL}/profile.html?payment=success`,
      cancel_url: `${FRONTEND_URL}/premium.html?payment=cancelled`,
    });

    console.log(`✅ Checkout session created: ${session.id} for ${userEmail}`);
    res.json({ id: session.id });
  } catch (err) {
    console.error("❌ Stripe checkout error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ✅ STRIPE: CANCEL SUBSCRIPTION
// ============================================================
app.post("/cancel-subscription", async (req, res) => {
  const { userId, collection } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "userId required" });
  }

  try {
    const col = collection || "users";
    const userDoc = await db.collection(col).doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const userData = userDoc.data();
    const subscriptionId = userData.stripeSubscriptionId;

    if (!subscriptionId) {
      return res.status(400).json({ error: "No active subscription found" });
    }

    // Stripe pe subscription cancel karo (period end pe cancel hoga)
    await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true,
    });

    // Firebase update karo
    await db.collection(col).doc(userId).set(
      {
        planCancelRequested: true,
        planCancelRequestedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
      { merge: true }
    );

    console.log(`✅ Subscription cancel requested for user: ${userId}`);
    res.json({
      success: true,
      message: "Subscription will be cancelled at end of billing period",
    });
  } catch (err) {
    console.error("❌ Cancel subscription error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ✅ GET USER PLAN & PAYMENT HISTORY
// ============================================================
app.get("/user-plan/:userId", async (req, res) => {
  const { userId } = req.params;
  const collection = req.query.collection || "users";

  try {
    const userDoc = await db.collection(collection).doc(userId).get();

    if (!userDoc.exists) {
      return res.json({ plan: "free", paymentHistory: [] });
    }

    const userData = userDoc.data();

    // Payment history fetch karo
    const historySnap = await db
      .collection(collection)
      .doc(userId)
      .collection("payment_history")
      .orderBy("paymentDate", "desc")
      .limit(20)
      .get();

    const paymentHistory = historySnap.docs.map((d) => d.data());

    res.json({
      plan: userData.plan || "free",
      planKey: userData.planKey || null,
      planStartDate: userData.planStartDate || null,
      planExpiryDate: userData.planExpiryDate || null,
      planCancelRequested: userData.planCancelRequested || false,
      stripeCustomerId: userData.stripeCustomerId || null,
      paymentHistory,
    });
  } catch (err) {
    console.error("❌ Get user plan error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// =====================
// START SERVER
// =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

module.exports = app;