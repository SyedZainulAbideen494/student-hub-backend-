const express = require("express");
const mysql = require("mysql2");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const PORT = process.env.PORT || 5000;
const axios = require('axios');
const cheerio = require('cheerio');
const querystring = require('querystring');
const nodemailer = require('nodemailer');
const request = require('request');
const webpush = require('web-push');
const crypto = require('crypto');
const cron = require('node-cron');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { HarmBlockThreshold, HarmCategory } = require("@google/generative-ai");
const pdfParse = require('pdf-parse');
const webPush = require('web-push');
const moment = require('moment');
const archiver = require("archiver");
const Razorpay = require('razorpay');
const fs = require('fs');

// Replace this line:
// const { GoogleGenAI, createUserContent, createPartFromUri } = require("@google/genai");

// With this:
let GoogleGenAI, createUserContent, createPartFromUri;
(async () => {
  const genai = await import('@google/genai');
  GoogleGenAI = genai.GoogleGenAI;
  createUserContent = genai.createUserContent;
  createPartFromUri = genai.createPartFromUri;
})();

// Initialize Google Generative AI
const genAI = new GoogleGenerativeAI('AIzaSyAhvINxPJMSHqKFA-oyBxEsuYxwBZtgPhA');

const safetySettings = [
  {
    category: HarmCategory.HARM_CATEGORY_HARASSMENT,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    threshold: HarmBlockThreshold.BLOCK_NONE
  },
  {
    category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
    threshold: HarmBlockThreshold.BLOCK_NONE
  }
];
const model = genAI.getGenerativeModel({
  model: "gemini-2.0-flash",
  safetySettings: safetySettings,
  systemInstruction: "You are FitBuddy, an AI-powered fitness and nutrition assistant designed to help users stay healthy, manage their diet, and achieve their fitness goals. Your mission is to provide personalized workout plans, meal guidance, and easy calorie tracking in a simple, accessible way.\n\n" +

  "- **Onboarding & Profile Setup**: Users create an account with email, password, and phone number. They enter personal data such as age, gender, height, weight, activity level, fitness goals (lose, gain, maintain weight), and dietary preferences (vegetarian, non-vegetarian, vegan, allergies). Based on this data, you generate a personalized fitness and nutrition profile.\n" +

  "- **Weekly Plans**: Generate a weekly schedule (Sunday to Saturday) that includes daily calorie targets, detailed meal plans with macronutrient breakdowns, and bodyweight workout plans. Meal plans adapt to dietary preferences, and workouts are equipment-free for accessibility.\n" +

  "- **Daily Calorie & Nutrition Tracking**: Users can log food by uploading images or typing text. When a photo is uploaded, analyze it to identify the food, estimate portion size, and calculate calories/macros. When text is entered (e.g., '2 rotis + dal'), parse it and estimate calories/nutrients. Always provide editable results so the user can confirm or adjust before saving.\n" +

  "- **Workout Plans**: Provide structured daily workout routines based on user profile. Workouts should include sets, reps, and rest times. Encourage consistency by offering progress tracking, streaks, and motivational messages.\n" +

  "- **WhatsApp Integration**: Users receive a daily greeting via WhatsApp with two quick options: [Workout Plan] and [Calories Tracker].\n" +
  "   • If [Workout Plan] is selected, send today’s workout routine.\n" +
  "   • If [Calories Tracker] is selected, send a summary of calories consumed, calories remaining, and allow the user to add new food entries via text or photo.\n" +

  "- **Progress Tracking**: Track calories consumed vs. target, completed workouts, and weekly progress. Provide summaries (daily, weekly) in-app and through WhatsApp.\n" +

  "- **AI Assistance**: Respond to user queries with practical fitness and nutrition advice. Always output clear, structured responses (tables, lists, or JSON when needed) that can be easily displayed in the app UI. If the user provides a broad request (like 'weight loss plan'), generate a complete summary plan instead of asking for excessive details.\n" +

  "- **Tone & Behavior**: Be supportive, encouraging, and motivating while staying practical. Avoid medical claims—add a disclaimer that results may vary and users should consult a healthcare professional for medical advice.\n\n" +

  "Your role is to act as a personal AI fitness buddy: generate weekly plans, track progress, estimate calories from text or photos, and keep users engaged through WhatsApp and in-app features. Always keep your responses concise, actionable, and user-friendly."
});


app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "500mb" }));
app.use(cookieParser());

app.use(session({
  key: "userId",
  secret: "Englishps4",
  resave: false,
  saveUninitialized: false,
  cookie: {
    expires: 60 * 60 * 24 * 12,
  },
}));

app.use(cors({
  origin: "*", // Allows requests from any origin
  methods: ["GET", "POST", "DELETE", "PUT"],
  credentials: true, // Allows cookies to be sent
}));

// Define storage for multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, 'public/');
  },
  filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, Date.now() + ext); // Append timestamp to filename to avoid collisions
  },
});

// File filter function
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
  } else {
      cb(new Error('Invalid file type'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 }, // Limit file size to 50 MB
});
// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

const connection = mysql.createPool({
  connectionLimit: 10, // Maximum number of connections in the pool
  host: "localhost",
  user: "root",
  password: "Englishps#4",
  database: "studenthub",
});

connection.getConnection((err) => {
  if (err) {
    console.error("Error connecting to MySQL database: ", err);
  } else {
    console.log("Connected to MySQL database");
  }
});

app.use(express.json());


const VERIFY_TOKEN = "EAAFsUoRPg1QBPhbJUdJfHq8BPiLdsv8m3kEZAH0ZAfFWbfBnvwDH07zGviQphQaubXao2n0op8TW0lZBWC1BQbNLzpSCFWhoh8BSP6XQ6YUTZAGsIlcljDfx7sl6VaZC3bwuRJ3dZBDXVAmWLREfNzsv5IRYEHbX3uGVWFkTs2U1NZC66Y3FqhFPejzbF3Vetdhv2FWuuVJs0KYW2UZCZAatuv1jDy1hnpq65E7j1cnPax09756DBE0kDSZB4z0ZCZCZCCAZDZD";


app.post("/webhook", (req, res) => {
    console.log("Ehllo")
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("Webhook verified!");
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// Function to send WhatsApp message
function sendWhatsAppMessage(data) {
  const config = {
    headers: {
      'Authorization': `Bearer ${VERIFY_TOKEN}`,
      'Content-Type': 'application/json'
    }
  };

  axios.post('https://graph.facebook.com/v19.0/332700683252247/messages', data, config)
    .then(response => {
      console.log('Message sent successfully:', response.data);
    })
    .catch(error => {
      console.error('Error sending message:', error.response.data);
    });
}

app.get('/', (req, res) => {
  // Send a JSON response indicating the server is working
  res.json({
    message: 'Server is working. You are being redirected...',
  });


});

// Utility function to extract user ID from token
const getUserIdFromToken = (token) => {
  return new Promise((resolve, reject) => {
    connection.query('SELECT user_id FROM session WHERE jwt = ?', [token], (err, results) => {
      if (err) {
        console.error(`Error fetching user_id for token: ${token}`, err);
        reject(new Error('Failed to authenticate user.'));
      }

      if (results.length === 0) {
        console.error(`Invalid or expired token: ${token}`);
        reject(new Error('Invalid or expired token.'));
      } else {
        resolve(results[0].user_id);
      }
    });
  });
};

// Promisify query function
const query = (sql, params) => {
  return new Promise((resolve, reject) => {
    connection.query(sql, params, (error, results) => {
      if (error) {
        reject(error);
      } else {
        resolve(results);
      }
    });
  });
};

// In-memory user states
const userStates = {};

// Helper: convert phone to international format
function toIntlPhone(phone) {
  phone = phone.replace(/\D/g, ''); // remove non-numeric
  if (phone.length === 9) return '91' + phone;
  if (phone.length === 10 && phone.startsWith('0')) return '91' + phone.slice(1);
  if (phone.length === 10) return '91' + phone; 
  return phone; // assume already in correct format
}

// WhatsApp webhook
app.post('/webhook/automation', async (req, res) => {
  console.log('Incoming POST request:', JSON.stringify(req.body, null, 2));

  try {
    const entry = req.body?.entry?.[0];
    const change = entry?.changes?.[0];
    const messages = change?.value?.messages;
    if (!messages) return res.sendStatus(200);

    const message = messages[0];
    const senderId = message.from; // WhatsApp phone number like 91776037290
    const messageType = message.type;

    // Initialize user state
    if (!userStates[senderId]) userStates[senderId] = { step: 0, data: {} };

    // Extract message body
    let messageBody = '';
    if (message.type === 'text') {
      messageBody = message.text.body.toLowerCase();
    } else if (message.type === 'interactive' && message.interactive.type === 'button_reply') {
      messageBody = message.interactive.button_reply.id.toLowerCase();
    }

    // Convert senderId to international format
    const phoneIntl = toIntlPhone(senderId);

    // Get user_id from phone
    const users = await query(`SELECT id FROM users WHERE phone_number = ?`, [phoneIntl]);
    console.log(phoneIntl)
    if (!users.length) {
      sendWhatsAppMessage({
        messaging_product: "whatsapp",
        to: senderId,
        type: "text",
        text: { body: "User not found in database." }
      });
      return res.sendStatus(200);
    }
    const userId = users[0].id;

    // Get today's weekday
    const todayDay = new Date().toLocaleDateString('en-US', { weekday: 'long' });

    if (messageBody === 'hi') {
      // Show interactive buttons
      sendWhatsAppMessage({
        messaging_product: "whatsapp",
        to: senderId,
        type: "interactive",
        interactive: {
          type: "button",
          body: { text: "Welcome! Choose an option to get started:" },
          action: {
            buttons: [
              { type: "reply", reply: { id: "workout_btn", title: "💪 Workout Plan" } },
              { type: "reply", reply: { id: "diet_btn", title: "🥗 Diet Plan" } }
            ]
          }
        }
      });

   } else if (messageBody === 'workout_btn') {
  const workoutRows = await query(
    `SELECT exercise, sets, reps, duration_minutes, notes
     FROM workouts
     WHERE user_id = ? AND day = ?`,
    [userId, todayDay]
  );

  const workoutText = workoutRows.length
    ? workoutRows.map((w, i) =>
        `🔹 *${i + 1}. ${w.exercise}*\n   ${w.sets} sets × ${w.reps} reps  •  ⏱ ${w.duration_minutes || 0} min${w.notes ? `\n   📝 ${w.notes}` : ""}`
      ).join("\n\n")
    : "✨ No workouts scheduled for today.";

  sendWhatsAppMessage({
    messaging_product: "whatsapp",
    to: senderId,
    type: "interactive",
    interactive: {
      type: "button",
      body: {
        text: `🏋️ *Today's Workout Plan*\n\n${workoutText}`
      },
      action: {
        buttons: [
          { type: "reply", reply: { id: "diet_btn", title: "🥗 View Diet Plan" } },
          { type: "reply", reply: { id: "workout_btn", title: "🔄 Refresh Workout" } }
        ]
      }
    }
  });


    } else if (messageBody === 'diet_btn') {
  const nutritionRows = await query(
    `SELECT n.calories, n.protein, n.carbs, n.fat,
            COALESCE(SUM(m.calories),0) AS consumed_calories,
            COALESCE(SUM(m.protein),0) AS consumed_protein,
            COALESCE(SUM(m.carbs),0) AS consumed_carbs,
            COALESCE(SUM(m.fat),0) AS consumed_fat
     FROM nutrition n
     LEFT JOIN userMealPhotos m 
       ON m.user_id = n.user_id AND DAYNAME(m.created_at) = n.day
     WHERE n.user_id = ? AND n.day = ?
     GROUP BY n.id`,
    [userId, todayDay]
  );

  if (nutritionRows.length) {
    const n = nutritionRows[0];
    const remainingCalories = n.calories - n.consumed_calories;
    const remainingProtein = n.protein - n.consumed_protein;
    const remainingCarbs = n.carbs - n.consumed_carbs;
    const remainingFat = n.fat - n.consumed_fat;

    const dietText = 
`🍽️ *Today's Diet Overview*
━━━━━━━━━━━━━━━
🎯 *Target*  
${n.calories} cal | ${n.protein}g P | ${n.carbs}g C | ${n.fat}g F

✅ *Consumed*  
${n.consumed_calories} cal | ${n.consumed_protein}g P | ${n.consumed_carbs}g C | ${n.consumed_fat}g F

📉 *Remaining*  
${remainingCalories} cal | ${remainingProtein}g P | ${remainingCarbs}g C | ${remainingFat}g F`;

    sendWhatsAppMessage({
      messaging_product: "whatsapp",
      to: senderId,
      type: "interactive",
      interactive: {
        type: "button",
        body: { text: dietText },
        action: {
          buttons: [
            { type: "reply", reply: { id: "workout_btn", title: "💪 View Workout Plan" } },
            { type: "reply", reply: { id: "diet_btn", title: "🔄 Refresh Diet" } }
          ]
        }
      }
    });

  } else {
    sendWhatsAppMessage({
      messaging_product: "whatsapp",
      to: senderId,
      type: "text",
      text: { body: "🚫 No diet plan found for today." }
    });
  }
} else {
  try {
    const aiResponse = await askFitnessAI(userId, messageBody);
    sendWhatsAppMessage({
      messaging_product: "whatsapp",
      to: senderId,
      type: "text",
      text: { body: aiResponse }
    });
  } catch (err) {
    console.error("AI response error:", err);
    sendWhatsAppMessage({
      messaging_product: "whatsapp",
      to: senderId,
      type: "text",
      text: { body: "Sorry, I couldn't process your request. Please try again." }
    });
  }
}


    res.sendStatus(200);

  } catch (err) {
    console.error('Webhook error:', err);
    res.sendStatus(500);
  }
});

const askFitnessAI = async (userId, userMessage) => {
  // Fetch user data
  const [user] = await query(`SELECT age, weight, height, gender, goal, activity, diet FROM user_fitness WHERE user_id = ? ORDER BY id DESC LIMIT 1`, [userId]);
  if (!user) throw new Error("No user fitness data found");

  const weeklyPlan = await query(`SELECT day, calories, protein, carbs, fat FROM nutrition WHERE user_id = ?`, [userId]);
const now = new Date();
const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' });
const currentHour = now.getHours();
const currentTime = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
const todayNutrition = await query(
  `SELECT calories, protein, carbs, fat FROM nutrition WHERE user_id = ? AND day = ?`,
  [userId, currentDay]
);

const todayWorkouts = await query(
  `SELECT exercise, sets, reps, duration_minutes FROM workouts WHERE user_id = ? AND day = ?`,
  [userId, currentDay]
);

const prompt = `
You are a friendly, encouraging, and highly motivating fitness AI buddy for a user. 
Speak politely, cheerfully, and motivate the user in every response. 
Always provide personalized advice based on the user's profile, weekly plan, today's status, and current time. 
Format responses for WhatsApp with line breaks, bullet points, emojis, and clear instructions.

User profile:
- Age: ${user.age}  
- Weight: ${user.weight} kg  
- Height: ${user.height} cm  
- Gender: ${user.gender}  
- Goal: ${user.goal}  
- Activity: ${user.activity}  
- Diet: ${user.diet}  

Current day & time:
- Day: ${currentDay}  
- Time: ${currentTime}  

Today's nutrition goal:
${todayNutrition.length ? `- Calories: ${todayNutrition[0].calories} cal | Protein: ${todayNutrition[0].protein}g | Carbs: ${todayNutrition[0].carbs}g | Fat: ${todayNutrition[0].fat}g` : 'No data'}

Today's workouts:
${todayWorkouts.length ? todayWorkouts.map((w,i) => `- ${w.exercise}: ${w.sets || 0} sets × ${w.reps || 0} reps, ${w.duration_minutes || 0} min`).join("\n") : 'No workouts scheduled'}

Weekly nutrition plan:
${weeklyPlan.map(w => `*${w.day}*: ${w.calories} cal | ${w.protein}g P | ${w.carbs}g C | ${w.fat}g F`).join("\n")}

The user asked: "${userMessage}"

Instructions for AI:
- Respond in a positive, motivating tone.
- Include encouragement like "You got this!", "Keep going!", "You're doing amazing!" where suitable.
- Give clear, actionable advice for workouts, diet, or general fitness.
- Suggest time-appropriate actions (e.g., breakfast, lunch, dinner, morning/evening workout).
- Format the response nicely for WhatsApp: line breaks, bullet points, and emojis.
- Keep the answer concise, friendly, and easy to follow.

Respond only in WhatsApp-friendly text format.
`;


  const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash", safetySettings });
  const chat = model.startChat({ history: [] });
  const result = await chat.sendMessage(prompt);
  const answer = await result.response.text();
  return answer.replace(/```/g, "").trim();
};

app.post("/ask-fitness", async (req, res) => {
  try {
    const { token, message } = req.body;
    const userId = await getUserIdFromToken(token);

    if (!userId) return res.status(401).json({ error: "Invalid token" });

    const answer = await askFitnessAI(userId, message);
    res.json({ answer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  }
});


app.post('/signup', (req, res) => {
  const { email, password, phone_number } = req.body;

  if (!email || !password || !phone_number) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const checkQuery = 'SELECT * FROM users WHERE email = ? OR phone_number = ?';
  connection.query(checkQuery, [email, phone_number], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('🔴 Error checking existing user:', checkErr);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (checkResults.length > 0) {
      return res.status(400).json({ error: 'Email or phone number already in use' });
    }

    bcrypt.hash(password, saltRounds, (hashErr, hash) => {
      if (hashErr) {
        console.error('🔴 Error hashing password:', hashErr);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const insertQuery = 'INSERT INTO users (password, email, phone_number) VALUES (?, ?, ?)';
      const values = [hash, email, phone_number];

      connection.query(insertQuery, values, (insertErr, insertResults) => {
        if (insertErr) {
          console.error('🔴 Error inserting user:', insertErr);
          return res.status(500).json({ error: 'Internal server error' });
        }

        const userId = insertResults.insertId;
        const token = jwt.sign({ id: userId }, 'jwtsecret', { expiresIn: '24h' });

        const sessionQuery = 'INSERT INTO session (user_id, jwt) VALUES (?, ?)';
        connection.query(sessionQuery, [userId, token], (sessionErr) => {
          if (sessionErr) {
            console.error('🔴 Error creating session:', sessionErr);
            return res.status(500).json({ error: 'Error creating session' });
          }

          // 1-day free premium
          const subQuery = `
            INSERT INTO subscriptions (user_id, subscription_plan, payment_status, payment_date, expiry_date)
            VALUES (?, '1-Day Plan', 'Paid', NOW(), DATE_ADD(NOW(), INTERVAL 1 DAY))
          `;
          connection.query(subQuery, [userId], (subErr) => {
            if (subErr) {
              console.error('🔴 Error giving free premium:', subErr);
              return res.status(500).json({ error: 'Error giving free premium' });
            }

            console.log('✅ User registered with 1-day premium!');
            return res.status(200).json({
              auth: true,
              token: token,
              user: { id: userId, email, phone_number },
              message: 'User registered and 1-day premium activated!'
            });
          });
        });
      });
    });
  });
});


const verifyjwt = (req, res) => {
  const token = req.headers["x-access-token"];

  if (!token) {
    res.send("no token unsuccessfull");
  } else {
    jwt.verify(token, "jwtsecret", (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: "u have failed to auth" });
      } else {
        req.user_id = decoded.id;
      }
    });
  }
};

app.get("/userAuth", verifyjwt, (req, res) => {});



function generateOTP() {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < 6; i++) {
      otp += digits[Math.floor(Math.random() * 10)];
  }
  return otp;
}

// Route to end the current event
const transporterSec = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: 'edusiyfy@gmail.com',
      pass: 'hvht twsf ejma juft',
  },
});


// Route to end the current event
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: 'edusyfy@gmail.com',
      pass: 'xqfw mmov xlrg gukf',
  },
});


app.post("/login", (req, res) => {
  const identifier = req.body.identifier;
  const password = req.body.password;

  if (!identifier || !password) {
    return res.status(400).json({ auth: false, message: "Identifier and password are required" });
  }

  let query;
  if (identifier.includes('@')) {
    query = "SELECT * FROM users WHERE email = ?";
  } else {
    query = "SELECT * FROM users WHERE phone_number = ?";
  }

  connection.query(query, [identifier], (err, result) => {
    if (err) return res.status(500).send({ message: "Database error", error: err });

    if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (error, response) => {
        if (error) return res.status(500).send({ message: "Password comparison error", error });

        if (response) {
          const userId = result[0].id;
          const token = jwt.sign({ id: userId }, "jwtsecret", { expiresIn: 86400 });

          connection.query(
            "INSERT INTO session (user_id, jwt) VALUES (?, ?)",
            [userId, token],
            (sessionErr) => {
              if (sessionErr) return res.status(500).send({ message: "Error creating session", error: sessionErr });
              res.json({ auth: true, token: token, result: result[0] });
            }
          );
        } else {
          res.json({ auth: false, message: "Incorrect password" });
        }
      });
    } else {
      res.json({ auth: false, message: "User not found" });
    }
  });
});   
app.post("/api/saveFitnessGoal", async (req, res) => {
  const { token, data } = req.body;

  const MAX_ATTEMPTS = 5;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    // Save raw user info once
    await query(
      `INSERT INTO user_fitness (user_id, age, weight, height, gender, goal, activity, diet) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, data.age, data.weight, data.height, data.gender, data.goal, data.activity, data.diet]
    );

 const prompt = `
Generate a 7-day fitness and nutrition plan for this user:
Age: ${data.age}, Weight: ${data.weight}, Height: ${data.height},
Gender: ${data.gender}, Goal: ${data.goal}, Activity: ${data.activity}, Diet: ${data.diet}.

For each day, provide details for:

Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday.

Each day should have:

1. Nutrition: calories, protein, carbs, fat, optional notes/tips.
2. Workout: list of exercises with sets, reps, duration_minutes if applicable.

Respond strictly in JSON format like this:

{
  "weeklyPlan": [
    {
      "day": "Monday",
      "nutrition": {"calories": 2000, "protein": 100, "carbs": 250, "fat": 60, "notes": "Optional tips"},
      "workout": [
        {"exercise": "Push-ups", "sets": 3, "reps": 15, "duration_minutes": null},
        {"exercise": "Jogging", "sets": null, "reps": null, "duration_minutes": 30}
      ]
    },
    {
      "day": "Tuesday",
      "nutrition": {...},
      "workout": [...]
    },
    ...
    {
      "day": "Sunday",
      "nutrition": {...},
      "workout": [...]
    }
  ]
}

Ensure all 7 days are present and JSON is valid. Include realistic exercises and nutrition details based on user's goal and activity.
`;

    const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash", safetySettings });

    // --- Helper to generate plan ---
    const generateFitnessPlan = async () => {
      const chat = model.startChat({ history: [] });
      const result = await chat.sendMessage(prompt);
      const rawResponse = await result.response.text();
      const sanitized = rawResponse.replace(/```(?:json)?/g, "").trim();
      const parsed = JSON.parse(sanitized);

      if (!parsed.weeklyPlan || !Array.isArray(parsed.weeklyPlan)) {
        throw new Error("AI response missing 'weeklyPlan' or it's not an array");
      }

      return parsed;
    };

    // --- Helper to insert into DB ---
    const insertPlanToDB = async (fitnessPlan) => {
      for (let dayPlan of fitnessPlan.weeklyPlan) {
        await query(
          `INSERT INTO nutrition (user_id, day, calories, protein, carbs, fat, notes) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [userId, dayPlan.day, dayPlan.nutrition.calories, dayPlan.nutrition.protein, dayPlan.nutrition.carbs, dayPlan.nutrition.fat, dayPlan.nutrition.notes || ""]
        );

        for (let exercise of dayPlan.workout) {
          await query(
            `INSERT INTO workouts (user_id, day, exercise, sets, reps, duration_minutes) VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, dayPlan.day, exercise.exercise, exercise.sets, exercise.reps, exercise.duration_minutes || null]
          );
        }
      }
    };

    // --- Unified retry loop ---
    let attempt = 0;
    let fitnessPlan = null;

    while (attempt < MAX_ATTEMPTS) {
      try {
        console.log(`Attempt ${attempt + 1} to generate & save plan...`);
        fitnessPlan = await generateFitnessPlan();
        await insertPlanToDB(fitnessPlan);

        // Success → break
        return res.json({ success: true, message: "Fitness plan saved successfully!", fitnessPlan });
      } catch (err) {
        attempt++;
        console.error(`Attempt ${attempt} failed:`, err.message);

        if (attempt >= MAX_ATTEMPTS) {
          throw new Error("Failed to generate and save fitness plan after multiple attempts.");
        }

        // wait before retry
        await new Promise(r => setTimeout(r, 2000));
      }
    }

  } catch (err) {
    console.error("Final error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});


app.get("/api/getFitnessPlan", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    // Fetch nutrition for user
    const nutritionRows = await query(
      `SELECT day, calories, protein, carbs, fat, notes FROM nutrition WHERE user_id = ? ORDER BY FIELD(day, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')`,
      [userId]
    );

    // Fetch workouts for user
    const workoutsRows = await query(
      `SELECT day, exercise, sets, reps, duration_minutes FROM workouts WHERE user_id = ? ORDER BY FIELD(day, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')`,
      [userId]
    );

    // Combine into weeklyPlan
    const weeklyPlan = nutritionRows.map(nutrition => {
      const dayWorkouts = workoutsRows.filter(w => w.day === nutrition.day);
      return {
        day: nutrition.day,
        nutrition: {
          calories: nutrition.calories,
          protein: nutrition.protein,
          carbs: nutrition.carbs,
          fat: nutrition.fat,
          notes: nutrition.notes
        },
        workout: dayWorkouts.map(w => ({
          exercise: w.exercise,
          sets: w.sets,
          reps: w.reps,
          duration_minutes: w.duration_minutes
        }))
      };
    });

    res.json({ success: true, fitnessPlan: { weeklyPlan } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});


app.get("/api/dashboard", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ success: false, error: "No token provided" });

    const token = authHeader.split(" ")[1];
    if (!token)
      return res.status(401).json({ success: false, error: "Invalid token format" });

    const userId = await getUserIdFromToken(token);
    if (!userId)
      return res.status(401).json({ success: false, error: "Invalid token" });

    const todayDate = new Date();
    const todayISO = todayDate.toISOString().split("T")[0]; // "2025-09-22"
    const todayDay = todayDate.toLocaleDateString("en-US", { weekday: "long" });

    // Fetch daily targets
    const targetRows = await query(
      "SELECT * FROM nutrition WHERE user_id=? AND day=?",
      [userId, todayDay]
    );

    if (!targetRows.length) {
      return res.json({ success: false, message: "No targets for today" });
    }

    const target = targetRows[0];

    // Fetch meals logged today
    const meals = await query(
      "SELECT * FROM userMealPhotos WHERE user_id=? AND date=?",
      [userId, todayISO]
    );

    // Sum consumed nutrients
    const consumed = meals.reduce(
      (acc, meal) => {
        acc.calories += meal.calories || 0;
        acc.protein += meal.protein || 0;
        acc.carbs += meal.carbs || 0;
        acc.fat += meal.fat || 0;
        return acc;
      },
      { calories: 0, protein: 0, carbs: 0, fat: 0 }
    );

    // Calculate remaining
    const remaining = {
      calories: Math.max(target.calories - consumed.calories, 0),
      protein: Math.max(target.protein - consumed.protein, 0),
      carbs: Math.max(target.carbs - consumed.carbs, 0),
      fat: Math.max(target.fat - consumed.fat, 0),
    };

    res.json({ success: true, target, consumed, remaining, meals });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});


// Set max file size for meal images (e.g., 50MB)
const MEAL_MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
// Multer setup for meal image uploads (store in memory temporarily)
const uploadMeal = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Unsupported image format'), false);
  },
});

// Helper function to save buffer to public folder
const saveImageToPublic = (file) => {
  return new Promise((resolve, reject) => {
    try {
      const ext = path.extname(file.originalname); // e.g., .jpg
      const fileName = `meal_${Date.now()}${ext}`;
      const filePath = path.join(__dirname, 'public', fileName);

      fs.writeFile(filePath, file.buffer, (err) => {
        if (err) return reject(err);
        resolve(fileName); // return only the filename
      });
    } catch (err) {
      reject(err);
    }
  });
};

// POST endpoint to upload meal image
app.post('/api/upload-meal', uploadMeal.single('image'), async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required.' });

    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ error: 'Invalid token or user not authenticated.' });

    if (!req.file) return res.status(400).json({ error: 'Meal image is required.' });

    console.log('Processing meal image...');
    const fileName = await saveImageToPublic(req.file); // save file and get filename

    // Convert image to Base64 for AI processing
    const imageBase64 = req.file.buffer.toString('base64');

    // Send image to AI model to extract nutrients
    const aiResponse = await model.generateContent([
      { inlineData: { data: imageBase64, mimeType: req.file.mimetype } },
      "Extract calories, protein (g), carbs (g), fat (g) from this meal and return **ONLY JSON**, like: { calories: number, protein: number, carbs: number, fat: number }. No extra text or explanations."
    ]);

    const nutrientsText = aiResponse?.response?.candidates?.[0]?.content?.parts?.[0]?.text;
    console.log('AI Response:', nutrientsText);
    if (!nutrientsText) throw new Error('No AI response received.');

    // Extract JSON safely from AI response
    let nutrients;
    try {
      const jsonMatch = nutrientsText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON found in AI response.');
      nutrients = JSON.parse(jsonMatch[0]);
    } catch (err) {
      throw new Error('Failed to parse AI nutrient response.');
    }

    // Get today's date
    const today = new Date();
    const dateISO = today.toISOString().split("T")[0];

    // Insert meal record into DB
// Insert meal record into DB
const result = await query(
  'INSERT INTO userMealPhotos (user_id, date, calories, protein, carbs, fat, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
  [userId, dateISO, nutrients.calories, nutrients.protein, nutrients.carbs, nutrients.fat, fileName]
);
const mealId = result.insertId;
// Send WhatsApp notification
const userRows = await query('SELECT phone_number FROM users WHERE id = ?', [userId]);
if (userRows.length) {
  const phone = userRows[0].phone_number;

  // Calculate remaining macros for today (optional, like in diet_btn)
  const todayMeals = await query(
    `SELECT COALESCE(SUM(calories),0) AS consumed_calories,
            COALESCE(SUM(protein),0) AS consumed_protein,
            COALESCE(SUM(carbs),0) AS consumed_carbs,
            COALESCE(SUM(fat),0) AS consumed_fat
     FROM userMealPhotos
     WHERE user_id = ? AND date = ?`,
    [userId, dateISO]
  );

  const consumed = todayMeals[0] || { consumed_calories: 0, consumed_protein: 0, consumed_carbs: 0, consumed_fat: 0 };

  const mealMessage = 
`🍴 *Meal Logged Successfully!*
━━━━━━━━━━━━━━━
🆕 *This Meal*
• Calories: ${nutrients.calories} kcal
• Protein: ${nutrients.protein} g
• Carbs: ${nutrients.carbs} g
• Fat: ${nutrients.fat} g

📊 *Today’s Total Intake*
• Calories: ${consumed.consumed_calories} kcal
• Protein: ${consumed.consumed_protein} g
• Carbs: ${consumed.consumed_carbs} g
• Fat: ${consumed.consumed_fat} g

✅ Keep it up! Track more meals in your app.
`;

  sendWhatsAppMessage({
    messaging_product: "whatsapp",
    to: phone,
    type: "text",
    text: { body: mealMessage }
  });
}


res.json({
  success: true,
  id: mealId,
  nutrients,
  message: 'Meal uploaded and nutrients extracted successfully.',
  imageUrl: `${fileName}`
});

  } catch (err) {
    console.error('Error uploading meal:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/meal/:id', async (req, res) => {
  try {
    const [meal] = await query('SELECT * FROM userMealPhotos WHERE id = ?', [req.params.id]);
    if (!meal) return res.status(404).json({ success: false, error: "Meal not found" });
    res.json({ success: true, meal });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to fetch meal" });
  }
});

// GET /dietplan
app.get('/dietplan', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ success: false, error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!token)
      return res.status(401).json({ success: false, error: 'Invalid token format' });

    const userId = await getUserIdFromToken(token);
    if (!userId)
      return res.status(401).json({ success: false, error: 'Invalid token' });

    // Fetch diet/nutrition plan for this user
    const rows = await query(
      `SELECT id, day, calories, protein, carbs, fat, notes, created_at
       FROM nutrition
       WHERE user_id = ?
       ORDER BY created_at ASC`,
      [userId]
    );

    // Transform into structured array (group by day)
    const planMap = {};
    rows.forEach(row => {
      if (!planMap[row.day]) {
        planMap[row.day] = {
          day: row.day,
          calories: row.calories,
          protein: row.protein,
          carbs: row.carbs,
          fat: row.fat,
          notes: row.notes,
          meals: []  // you can optionally add meals later if needed
        };
      }
    });

    res.json({ success: true, plan: Object.values(planMap) });

  } catch (err) {
    console.error('Error fetching diet plan:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /workouts
app.get('/workouts', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ success: false, error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    const userId = await getUserIdFromToken(token);
    if (!userId)
      return res.status(401).json({ success: false, error: 'Invalid token' });

    // Fetch workouts for this user
    const workoutRows = await query(
      `SELECT id, day, exercise, sets, reps, duration_minutes, notes
       FROM workouts
       WHERE user_id = ?
       ORDER BY FIELD(day,'Mon','Tue','Wed','Thu','Fri','Sat','Sun'), id`,
      [userId]
    );

    res.json({ success: true, workouts: workoutRows });

  } catch (err) {
    console.error('Error fetching workouts:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

