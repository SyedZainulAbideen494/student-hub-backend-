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
const PORT = process.env.PORT || 8080;
const axios = require('axios');
const cheerio = require('cheerio');
const querystring = require('querystring');
const nodemailer = require('nodemailer');
const request = require('request');
const webpush = require('web-push');
const crypto = require('crypto');
const stripe = require('stripe')('sk_test_51LoS3iSGyKMMAZwstPlmLCEi1eBUy7MsjYxiKsD1lT31LQwvPZYPvqCdfgH9xl8KgeJoVn6EVPMgnMRsFInhnnnb00WhKhMOq7');
const cron = require('node-cron');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { HarmBlockThreshold, HarmCategory } = require("@google/generative-ai");
const schedule = require("node-schedule");
const pdfParse = require('pdf-parse');
const fs = require('fs');
const webPush = require('web-push');
const { speechToText, textToSpeech } = require('./speechService'); // Speech service (speech-to-text and text-to-speech)
const moment = require('moment');
const Razorpay = require('razorpay');
// Initialize Google Generative AI
const genAI = new GoogleGenerativeAI('AIzaSyCvmpjZRi7GGS9TcPQeVCnSDJLFPchYZ38');

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
  model: "gemini-1.5-flash-8b",
  safetySettings: safetySettings,
  systemInstruction: "You are Edusify, an AI-powered productivity assistant designed to help students manage their academic tasks, study materials, and stay organized. Your mission is to provide tailored assistance and streamline the study experience with a wide range of features. Below are the core functionalities that you support: \n\n" +
  
  "- **Sticky Notes**: Users can quickly add sticky notes on the dashboard by clicking 'Add Note'. They can input a title, optional description, and select the note color. Notes are saved for easy access and organization. The dashboard also displays today's tasks and events.\n" +
  
  "- **AI Assistant**: Edusify helps users by generating notes, quizzes, and even adding AI responses directly to their notes with the 'Magic' feature. Users can click on the 'Magic' button to generate content like quizzes and notes from their AI response and add that content to their study materials.\n" +
  
  "- **To-Do List**: The To-Do List helps users manage their tasks more efficiently. Tasks can be created with a title, description, due date, priority level, and email reminders. AI can even generate tasks based on user input or upcoming deadlines.\n" +
  
  "- **Notes**: Users can create notes by going to the 'Notes' section and clicking 'Create Notes'. They can input a name and description for the note, select a subject category, and optionally add images. Notes are customizable and can be saved for future reference. Additionally, users can generate flashcards and quizzes from their notes for better retention.\n" +
  
  "- **Flashcards**: Users can create flashcards manually, from AI-generated content, or by uploading PDFs. When uploading PDFs, Edusify extracts text and generates relevant flashcards. Flashcards can be customized, saved, and studied.\n" +
  
  "- **Rooms**: Rooms allow users to create or join study groups where they can share resources, track each other's progress, and collaborate on projects. Rooms help create a sense of community for focused learning.\n" +
  
  "- **Quizzes**: Users can generate quizzes manually, with AI, or from PDFs. AI can help generate relevant quiz questions based on the user's study material, and quizzes can be shared with others for collaborative learning.\n" +
  
  "- **Document Locker**: A secure space where students can store important documents with the option to add password protection for extra security.\n" +
  
  "- **Calendar**: Users can track important dates like exams, assignments, and events, keeping their schedule organized and well-managed.\n" +
  
  "- **Pomodoro Timer**: The Pomodoro Timer helps users maintain focus with study sessions and breaks. It tracks study and break times, allowing users to monitor their productivity and download stats for social sharing.\n\n" +
  
  "Your goal is to provide a seamless and engaging experience by offering personalized study tools, helping students organize their academic tasks, and encouraging efficient study habits through the integration of AI-powered features. You are designed to assist students in staying on top of their goals, providing reminders, feedback, and support whenever needed."
});



app.use(express.urlencoded({ extended: true }));
app.use(express.json());
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
      cb(null, '/root/student-hub-backend-/public/');
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

const BASE_URL = 'https://srv594954.hstgr.cloud';
const FRONTEND_BASE_URL = 'https://edusify.vercel.app'; // Update this if your frontend runs on a different URL

// Backend success and cancel URLs
const SUCCESS_URL = `${BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}&sender_id=`;
const CANCEL_URL = `${BASE_URL}/cancel`;
const baseURL = 'https://dropment.online';


// Function to send WhatsApp message
function sendWhatsAppMessage(data) {
  const config = {
    headers: {
      'Authorization': 'Bearer EAAFsUoRPg1QBO6ZCbIX3mh0YL4VvkMJhzPovnNITFIDLsZCM6Y1fidZA8mfMm7ac5jXUugjZCsq10DB1YGTP62waRfLZBn7SYcgQVMD2SmH7H7wxfgd6hZBSjALEZC5rxCbyhPuertNehx0KIOqMVZBw5CGLOkQqd8IZA01tNTTtp45sNpDBMcSC7jtZBwzIEkxKdBYoZCTLm7OLZBEcXSm3',
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


// Generate VAPID keys once and keep them secure
const publicVapidKey = 'BLDWVHPzXRA9ZOFhSyCet2trdRuvErMUBKuUPNzDsffj-b3-yvd7z58UEhpQAu-MA3DREuu4LwQhspUKBD1yngs';
const privateVapidKey = 'm5wPuyP581Ndto1uRBwGufADT7shUIbfUyV6YQcv88Q';

webPush.setVapidDetails('mailto:zainkaleem27@gmail.com', publicVapidKey, privateVapidKey);

let subscriptions = [];

// Route to handle subscription
app.post('/subscribe/noti', (req, res) => {
  const subscription = req.body;
  subscriptions.push(subscription);
  res.status(201).json({});
});

// Route to send notifications
app.post('/send-notification', (req, res) => {
  const { title, message, icon } = req.body;
  const payload = JSON.stringify({ title, message, icon });

  subscriptions.forEach((subscription, index) => {
    webPush
      .sendNotification(subscription, payload)
      .catch((err) => {
        console.error('Push Error:', err);
        subscriptions.splice(index, 1); // Remove invalid subscriptions
      });
  });

  res.status(200).send('Notifications sent.');
});


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


// Webhook verification endpoint (GET request)
app.get('/webhook', (req, res) => {
  console.log('Query parameters:', req.query);
  const VERIFY_TOKEN = "EAAFsUoRPg1QBOzpnPGEpxBDKEw93j35D2V0Qg5C8O58FNQZAxWXWMo0XJZB6ezMoUWY6xNC6AhPGUZCjt0w8AJwuyAfkhjnZAn73tOU88pXhTxAJevtKm1GSGkDFwh5y79N1eX9LWhD3ceZAZBr36MDd1fgAy0m9UfVDIugUDGxcl64vAhpNuj7FkbG36HGJn3RQus1iw92DiNn4w"; // Replace with your verification token
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified!');
    res.status(200).send(challenge);
  } else {
    console.error('Failed verification. Make sure the verification tokens match.');
    res.sendStatus(403);
  }
});

app.post('/check-unique-id', (req, res) => {
  const { unique_id } = req.body;

  const checkUniqueIdQuery = 'SELECT * FROM users WHERE unique_id = ?';
  connection.query(checkUniqueIdQuery, [unique_id], (err, results) => {
    if (err) {
      console.error('Error checking unique_id:', err);
      res.status(500).json({ error: 'Internal server error' });
    } else if (results.length > 0) {
      // If unique_id already exists, return a message
      res.status(409).json({ error: 'Unique ID already taken' });
    } else {
      // If unique_id doesn't exist, return success
      res.status(200).json({ message: 'Unique ID available' });
    }
  });
});


app.post('/generate-alternatives', (req, res) => {
  const { unique_id } = req.body;
  
  // Generate some alternative unique IDs (mocked here for simplicity)
  const generateAlternatives = (base) => {
    const alternatives = [];
    for (let i = 1; i <= 5; i++) {
      alternatives.push(`${base}${i}`);
    }
    return alternatives;
  };

  // Generate alternatives based on the provided unique_id
  const alternatives = generateAlternatives(unique_id);
  res.status(200).json({ alternatives });
});


app.post('/signup', (req, res) => {
  const { password, email, unique_id, phone_number } = req.body;

  // Query to check if email or phone number already exists
  const checkQuery = 'SELECT * FROM users WHERE email = ? OR phone_number = ?';
  connection.query(checkQuery, [email, phone_number], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('Error checking existing user:', checkErr);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (checkResults.length > 0) {
      return res.status(400).json({ error: 'Email or phone number already in use' });
    }

    // Proceed with hashing the password and inserting the new user
    bcrypt.hash(password, saltRounds, (hashErr, hash) => {
      if (hashErr) {
        console.error('Error hashing password:', hashErr);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const insertQuery = 'INSERT INTO users (password, email, unique_id, phone_number) VALUES (?, ?, ?, ?)';
      const values = [hash, email, unique_id, phone_number];

      connection.query(insertQuery, values, (insertErr, insertResults) => {
        if (insertErr) {
          console.error('Error inserting user:', insertErr);
          return res.status(500).json({ error: 'Internal server error' });
        }

        // User successfully registered, now generate JWT token
        const userId = insertResults.insertId;
        const token = jwt.sign({ id: userId }, 'jwtsecret', { expiresIn: 86400 }); // 24 hours

        // Insert the token into the session table
        connection.query(
          'INSERT INTO session (user_id, jwt) VALUES (?, ?)',
          [userId, token],
          (sessionErr) => {
            if (sessionErr) {
              console.error('Error creating session:', sessionErr);
              return res.status(500).send({ message: 'Error creating session', error: sessionErr });
            }

            console.log('User registration and session creation successful!');
            res.json({ auth: true, token: token });
          }
        );
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
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: 'edusyfy@gmail.com',
      pass: 'xqfw mmov xlrg gukf',
  },
});

// Login route
app.post("/login", (req, res) => {
  const identifier = req.body.identifier;
  const password = req.body.password;

  let query;
  if (identifier.includes('@')) {
    query = "SELECT * FROM users WHERE email = ?";
  } else if (!isNaN(identifier)) {
    query = "SELECT * FROM users WHERE phone_number = ?";
  } else {
    query = "SELECT * FROM users WHERE unique_id = ?";
  }

  connection.query(query, [identifier], (err, result) => {
    if (err) return res.status(500).send({ message: "Database error", error: err });

    if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (error, response) => {
        if (error) return res.status(500).send({ message: "Password comparison error", error });

        if (response) {
          // Correct password
          const otp = generateOTP();
          connection.query(
            "INSERT INTO 2fa (phone_number, otp, active) VALUES (?, ?, 1)",
            [result[0].phone_number, otp],
            (err, otpResult) => {
              if (err) return res.status(500).send({ message: "Error generating OTP", error: err });

              // Send OTP via Email
              const mailOptions = {
                from: 'edusyfy@gmail.com',
                to: result[0].email,
                subject: 'Your OTP for Secure Login',
                html: `
                  <p>Hello ${result[0].unique_id},</p>
                  <p>We’ve received a login request for your account. To complete the login process, please use the One-Time Password (OTP) below:</p>
                  <h2>${otp}</h2>
                  <p>Enter this OTP on the login page to complete the process.</p>
                  <p>If you did not request this login, please ignore this email.</p>
                  <p>Best regards,<br>Edusify</p>
                `
              };

              transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                  console.log('Error sending email:', err);
                  return res.status(500).send({ message: "Error sending OTP email" });
                }
                console.log('Email sent:', info.response);
                res.json({ auth: true, message: "OTP sent for verification", phone: result[0].phone_number, email: result[0].email });
              });
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

// OTP verification route
app.post("/verify-otp", (req, res) => {
  const phone = req.body.phone;
  const otp = req.body.otp;

  if (!phone || !otp) return res.status(400).send({ message: "Phone and OTP are required" });

  connection.query(
      "SELECT * FROM 2fa WHERE phone_number = ? AND otp = ? AND active = 1 AND created_at >= NOW() - INTERVAL 2 MINUTE",
      [phone, otp],
      (err, result) => {
          if (err) return res.status(500).send({ message: "Database error while verifying OTP", error: err });

          if (result.length > 0) {
              connection.query(
                  "SELECT * FROM users WHERE phone_number = ?",
                  [phone],
                  (userErr, userResult) => {
                      if (userErr) return res.status(500).send({ message: "Database error while fetching user details", error: userErr });

                      if (userResult.length > 0) {
                          const userId = userResult[0].id;
                          connection.query(
                              "UPDATE 2fa SET active = 0 WHERE phone_number = ? AND otp = ?",
                              [phone, otp],
                              (updateErr) => {
                                  if (updateErr) return res.status(500).send({ message: "Error updating OTP status", error: updateErr });

                                  const token = jwt.sign({ id: userId }, "jwtsecret", { expiresIn: 86400 });
                                  connection.query(
                                      "INSERT INTO session (user_id, jwt) VALUES (?, ?)",
                                      [userId, token],
                                      (sessionErr) => {
                                          if (sessionErr) return res.status(500).send({ message: "Error creating session", error: sessionErr });
                                          res.json({ auth: true, token: token, result: userResult });
                                      }
                                  );
                              }
                          );
                      } else {
                          res.status(404).send({ message: "User not found" });
                      }
                  }
              );
          } else {
              res.json({ auth: false, message: "Invalid OTP or OTP expired" });
          }
      }
  );
});

app.post('/add/tasks', async (req, res) => {
  const { title, description, due_date, priority, email_reminder, token } = req.body;

  try {
    // Step 1: Get User ID
    const [userResults] = await connection.promise().query(
      'SELECT user_id FROM session WHERE jwt = ?',
      [token]
    );

    if (userResults.length === 0) {
      return res.status(404).send({ message: 'User not found' });
    }

    const user_id = userResults[0].user_id;

    // Step 2: Handle due_date
    const formattedDueDate = due_date ? due_date : new Date().toISOString().slice(0, 19).replace('T', ' ');

    // Step 3: Insert Task with email reminder
    const [insertResults] = await connection.promise().query(
      'INSERT INTO tasks (title, description, due_date, priority, email_reminder, user_id) VALUES (?, ?, ?, ?, ?, ?)',
      [title, description, formattedDueDate, priority, email_reminder, user_id]
    );

    // Step 4: Handle Points (unchanged)
    const [pointsResults] = await connection.promise().query(
      'SELECT points, updated_at FROM user_points WHERE user_id = ?',
      [user_id]
    );

    const currentTime = new Date();
    const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000); // Subtract 5 minutes

    let pointsToAdd = 5; // Default points to add
    if (pointsResults.length > 0) {
      const lastUpdated = new Date(pointsResults[0].updated_at);
      if (lastUpdated > fiveMinutesAgo) {
        pointsToAdd = 5; // Or any number you choose
      }

      await connection.promise().query(
        'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
        [pointsToAdd, currentTime, user_id]
      );
    } else {
      await connection.promise().query(
        'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
        [user_id, pointsToAdd, currentTime]
      );
    }

    // Step 5: Send response
    res.status(201).send({
      id: insertResults.insertId,
      title,
      description,
      due_date: formattedDueDate,
      priority,
      email_reminder,
      message: 'Task added and points updated successfully'
    });
  } catch (err) {
    console.error('Error adding task:', err);
    res.status(500).send({ message: 'Internal server error' });
  }
});


app.post('/fetch/tasks', (req, res) => {
  const { token } = req.body;

  const getUserQuery = 'SELECT user_id FROM session WHERE jwt = ?';
  connection.query(getUserQuery, [token], (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      if (results.length === 0) {
          return res.status(404).send({ message: 'User not found' });
      }

      const user_id = results[0].user_id;
      const fetchQuery = 'SELECT * FROM tasks WHERE user_id = ? AND completed = 0'; // Only fetch non-completed tasks
      connection.query(fetchQuery, [user_id], (err, results) => {
          if (err) {
              return res.status(500).send(err);
          }
          res.send(results);
      });
  });
});


app.post('/edit/task', (req, res) => {
  const { id, title, description, due_date, priority, email_reminder, token } = req.body;

  const getUserQuery = 'SELECT user_id FROM session WHERE jwt = ?';
  connection.query(getUserQuery, [token], (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      if (results.length === 0) {
          return res.status(404).send({ message: 'User not found' });
      }

      const user_id = results[0].user_id;
      const updateQuery = 'UPDATE tasks SET title = ?, description = ?, due_date = ?, email_reminder= ?, priority = ? WHERE id = ? AND user_id = ?';
      connection.query(updateQuery, [title, description, due_date, email_reminder, priority, id, user_id], (err, results) => {
          if (err) {
              return res.status(500).send(err);
          }
          res.send({ message: 'Task updated successfully' });
      });
  });
});

app.post('/delete/task', (req, res) => {
  const { id, token } = req.body;

  const getUserQuery = 'SELECT user_id FROM session WHERE jwt = ?';
  connection.query(getUserQuery, [token], (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      if (results.length === 0) {
          return res.status(404).send({ message: 'User not found' });
      }

      const user_id = results[0].user_id;
      const updateQuery = 'UPDATE tasks SET completed = 1, completed_at = ? WHERE id = ? AND user_id = ?';
      const completedAt = new Date();

      // Step 1: Update the Task to Completed
      connection.query(updateQuery, [completedAt, id, user_id], (err, updateResults) => {
          if (err) {
              return res.status(500).send(err);
          }

          // Step 2: Update Points
          const pointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';
          connection.query(pointsQuery, [user_id], (err, pointsResults) => {
              if (err) {
                  return res.status(500).send(err);
              }

              const currentTime = new Date();
              const twoMinutesAgo = new Date(currentTime.getTime() - 2 * 60000); // Subtract 2 minutes
              let pointsToAdd = 3; // Default points to add

              if (pointsResults.length > 0) {
                  // If user exists, check updated_at timestamp
                  const lastUpdated = new Date(pointsResults[0].updated_at);
                  if (lastUpdated > twoMinutesAgo) {
                      // If last update was less than 2 minutes ago, add 1 point
                      pointsToAdd = 1;
                  }

                  // Update points
                  connection.query(
                      'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
                      [pointsToAdd, currentTime, user_id],
                      (err) => {
                          if (err) {
                              return res.status(500).send(err);
                          }
                          res.send({ message: 'Task marked as completed and points updated.' });
                      }
                  );
              } else {
                  // If user does not exist, insert new record with the points
                  connection.query(
                      'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
                      [user_id, pointsToAdd, currentTime],
                      (err) => {
                          if (err) {
                              return res.status(500).send(err);
                          }
                          res.send({ message: 'Task marked as completed and points added.' });
                      }
                  );
              }
          });
      });
  });
});



async function sendTaskReminders() {
  try {
    // Step 1: Fetch tasks with email reminders
    const tasks = await query(`
      SELECT t.id, t.title, t.description, t.due_date, t.user_id, u.unique_id, u.email
      FROM tasks t
      JOIN users u ON t.user_id = u.id
      WHERE t.completed = 0 AND t.email_reminder = 1
    `);

    // Step 2: Filter out tasks with passed due dates and check if the due date is 1 day away
    const currentDateTime = new Date();
    const targetDate = new Date(currentDateTime);
    targetDate.setHours(0, 0, 0, 0); // Reset time for a clear comparison

    const oneDayLater = new Date(targetDate);
    oneDayLater.setDate(targetDate.getDate() + 1); // One day later

    const validTasks = tasks.filter((task) => {
      const dueDate = new Date(task.due_date);
      return dueDate > currentDateTime && dueDate <= oneDayLater;
    });

    // Step 3: Group valid tasks by user
    const userTasks = validTasks.reduce((acc, task) => {
      const userKey = task.user_id;
      if (!acc[userKey]) {
        acc[userKey] = { unique_id: task.unique_id, email: task.email, tasks: [] };
      }
      acc[userKey].tasks.push({
        title: task.title,
        description: task.description,
        due_date: task.due_date,
      });
      return acc;
    }, {});

    // Step 4: Send emails to each user
    for (const userId in userTasks) {
      const { unique_id, email, tasks } = userTasks[userId];
      const taskList = tasks
        .map(
          (task) =>
            `<li>
              <strong>${task.title}</strong><br>
              ${task.description ? `<em>${task.description}</em><br>` : ""}
              <strong>Due:</strong> ${new Date(task.due_date).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })}
            </li>`
        )
        .join("");

      const emailBody = `
        <div style="
          font-family: 'Helvetica Neue', Arial, sans-serif; 
          background-color: #f9f9f9; 
          padding: 20px; 
          border-radius: 10px; 
          max-width: 600px; 
          margin: auto; 
          box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); 
          color: #333;
        ">
          <h2 style="
            color: #000; 
            text-align: center; 
            margin-bottom: 20px; 
            font-weight: bold;
          ">
            Hello ${unique_id},
          </h2>
          <p style="font-size: 16px; line-height: 1.5; margin-bottom: 20px; text-align: center;">
            We hope you're doing great! Here's a summary of your pending tasks:
          </p>
          <ul style="
            background-color: #fff; 
            padding: 20px; 
            border-radius: 10px; 
            list-style: none; 
            margin: 0 auto 20px; 
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
          ">
            ${taskList}
          </ul>
          <p style="font-size: 16px; line-height: 1.5; text-align: center; margin-bottom: 20px;">
            Don't forget to stay on top of your tasks and keep making progress. Visit your planner to review and update your tasks:
          </p>
          <p style="text-align: center; margin-bottom: 20px;">
            <a 
              href="https://edusify.vercel.app/planner" 
              style="
                color: #fff; 
                background-color: #000; 
                padding: 12px 20px; 
                text-decoration: none; 
                border-radius: 25px; 
                font-weight: bold; 
                display: inline-block;
              "
            >
              Open Planner
            </a>
          </p>
          <p style="font-size: 14px; color: #555; text-align: center;">
            Stay productive! 😊
          </p>
          <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
          <p style="font-size: 12px; color: #aaa; text-align: center;">
            This email was sent by Edusify Task Reminder System. 
            <br>Visit <a href="https://edusify.vercel.app" style="color: #000; text-decoration: none;">edusify.vercel.app</a> for more.
          </p>
        </div>
      `;

      await transporter.sendMail({
        from: "edusify@gmail.com",
        to: email,
        subject: "Your Pending Tasks Reminder - Edusify",
        html: emailBody,
      });

      console.log(`Email sent to ${unique_id} (${email})`);
    }
  } catch (error) {
    console.error("Error sending task reminders:", error);
  }
}

// Schedule tasks
schedule.scheduleJob("0 7,15,20 * * *", async () => {
  console.log("Running task reminders at", new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }));
  await sendTaskReminders();
});


app.post('/api/add/flashcards', upload.array('images'), (req, res) => {
  const { title, description, isPublic, token, headings, subjectId } = req.body;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  connection.query('SELECT user_id FROM session WHERE jwt = ?', [token], (err, results) => {
    if (err) {
      console.error('Error fetching user_id:', err);
      return res.status(500).json({ message: 'Failed to authenticate user.' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid or expired token.' });
    }

    const userId = results[0].user_id;
    const imageNames = req.files ? req.files.map((file) => file.filename) : [];

    const query = `
      INSERT INTO flashcards (title, description, images, is_public, user_id, headings, subject_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [title, description, JSON.stringify(imageNames), isPublic, userId, headings, subjectId];

    connection.query(query, values, (error, results) => {
      if (error) {
        console.error('Error inserting flashcard:', error);
        return res.status(500).json({ message: 'Failed to save flashcard.' });
      }

      const flashcardId = results.insertId; // Get the newly inserted flashcard ID

      const pointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';
      connection.query(pointsQuery, [userId], (err, pointsResults) => {
        if (err) {
          console.error('Error fetching user points:', err);
          return res.status(500).json({ message: 'Failed to update points.' });
        }

        const currentTime = new Date();
        const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000);
        let pointsToAdd = 10;

        if (pointsResults.length > 0) {
          const lastUpdated = new Date(pointsResults[0].updated_at);
          if (lastUpdated > fiveMinutesAgo) {
            pointsToAdd = 10; // Add default points
          }

          connection.query(
            'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
            [pointsToAdd, currentTime, userId],
            (err) => {
              if (err) {
                console.error('Error updating points:', err);
                return res.status(500).json({ message: 'Failed to update points.' });
              }

              res.status(200).json({
                message: 'Flashcard saved successfully!',
                flashcardId: flashcardId,
              });
            }
          );
        } else {
          connection.query(
            'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
            [userId, pointsToAdd, currentTime],
            (err) => {
              if (err) {
                console.error('Error inserting points:', err);
                return res.status(500).json({ message: 'Failed to update points.' });
              }

              res.status(200).json({
                message: 'Flashcard saved successfully!',
                flashcardId: flashcardId,
              });
            }
          );
        }
      });
    });
  });
});



app.get('/api/get/user/notes', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
  }

  connection.query('SELECT user_id FROM session WHERE jwt = ?', [token], (err, results) => {
      if (err) {
          console.error('Error fetching user_id:', err);
          return res.status(500).json({ message: 'Failed to authenticate user.' });
      }

      if (results.length === 0) {
          return res.status(401).json({ message: 'Invalid or expired token.' });
      }

      const userId = results[0].user_id;

      connection.query('SELECT * FROM flashcards WHERE user_id = ?', [userId], (err, notes) => {
          if (err) {
              console.error('Error fetching notes:', err);
              return res.status(500).json({ message: 'Failed to retrieve notes.' });
          }
          res.json(notes);
      });
  });
});

// Route to get a specific note by ID
app.get('/api/notes/:id', (req, res) => {
  const noteId = req.params.id;

  connection.query('SELECT * FROM flashcards WHERE id = ?', [noteId], (error, results) => {
      if (error) {
          console.error('Error fetching note:', error);
          return res.status(500).json({ message: 'Internal Server Error' });
      }
      
      if (results.length > 0) {
          res.json(results[0]);
      } else {
          res.status(404).json({ message: 'Note not found' });
      }
  });
});

app.put('/api/update/note/:note_id', (req, res) => {
  const noteId = req.params.note_id;
  const { title, description, headings, subject } = req.body;

  const query = `
      UPDATE flashcards 
      SET title = ?, description = ?, headings = ?, subject_id = ?
      WHERE id = ?
  `;
  const values = [title, description, headings, subject, noteId];

  connection.query(query, values, (error, results) => {
      if (error) {
          console.error('Error updating note:', error);
          return res.status(500).json({ message: 'Failed to update note.' });
      }

      if (results.affectedRows === 0) {
          return res.status(404).json({ message: 'Note not found.' });
      }

      res.status(200).json({ message: 'Note updated successfully!' });
  });
});

// Route to delete a specific note by note_id
app.delete('/api/delete/note/:note_id', (req, res) => {
  const noteId = req.params.note_id;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
  }

  connection.query('SELECT user_id FROM session WHERE jwt = ?', [token], (err, results) => {
      if (err) {
          console.error('Error fetching user_id:', err);
          return res.status(500).json({ message: 'Failed to authenticate user.' });
      }

      if (results.length === 0) {
          return res.status(401).json({ message: 'Invalid or expired token.' });
      }

      const userId = results[0].user_id;

      const query = `
          DELETE FROM flashcards 
          WHERE id = ? AND user_id = ?
      `;
      const values = [noteId, userId];

      connection.query(query, values, (error, results) => {
          if (error) {
              console.error('Error deleting note:', error);
              return res.status(500).json({ message: 'Failed to delete note.' });
          }

          if (results.affectedRows === 0) {
              return res.status(404).json({ message: 'Note not found or not authorized.' });
          }

          res.status(200).json({ message: 'Note deleted successfully!' });
      });
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

// Route to fetch joined groups
app.get('/api/groups/joined', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(400).json({ message: 'Token is required' });
  }

  try {
      const userId = await getUserIdFromToken(token);

      connection.query(
          'SELECT g.* FROM `groups` g JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = ?',
          [userId],
          (error, results) => {
              if (error) {
                  console.error('Error fetching joined groups:', error);
                  return res.status(500).json({ message: 'Internal Server Error' });
              }
              res.status(200).json(results);
          }
      );
  } catch (error) {
      console.error('Error decoding token:', error);
      res.status(401).json({ message: error.message });
  }
});
// Route to get public groups
app.get('/api/groups/public', (req, res) => {
  connection.query('SELECT * FROM `groups` WHERE is_public = ?', ['1'], (error, results) => {
      if (error) {
          console.error('Error fetching public groups:', error);
          return res.status(500).json({ message: 'Internal Server Error' });
      }
      res.json(results);
  });
});
// Route to create a new group
app.post('/api/groups/add', async (req, res) => {
  const { name, description, is_public } = req.body;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(400).json({ message: 'Token is required' });
  }

  try {
      const userId = await getUserIdFromToken(token);

      connection.query(
          'INSERT INTO `groups` (name, description, is_public, user_id) VALUES (?, ?, ?, ?)',
          [name, description, is_public, userId],
          (error, results) => {
              if (error) {
                  console.error('Error creating group:', error);
                  return res.status(500).json({ message: 'Internal Server Error' });
              }
              const groupId = results.insertId;
              connection.query(
                  'INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)',
                  [userId, groupId],
                  (error) => {
                      if (error) {
                          console.error('Error adding user to group:', error);
                          return res.status(500).json({ message: 'Internal Server Error' });
                      }
                      res.status(201).json({ message: 'Group created successfully' });
                  }
              );
          }
      );
  } catch (error) {
      console.error('Error decoding token:', error);
      res.status(401).json({ message: error.message });
  }
});

// Route to join a group
app.post('/api/groups/join/:id', async (req, res) => {
  const groupId = req.params.id;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(400).json({ message: 'Token is required' });
  }

  try {
      const userId = await getUserIdFromToken(token);

      connection.query(
          'INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)',
          [userId, groupId],
          (error) => {
              if (error) {
                  console.error('Error joining group:', error);
                  return res.status(500).json({ message: 'Internal Server Error' });
              }
              res.status(200).json({ message: 'Joined group successfully' });
          }
      );
  } catch (error) {
      console.error('Error decoding token:', error);
      res.status(401).json({ message: error.message });
  }
});

app.get('/api/groups/:id', (req, res) => {
  const groupId = req.params.id;
  const query = `SELECT * FROM \`groups\` WHERE id = ?`;
  
  connection.query(query, [groupId], (err, results) => {
    if (err) {
      console.error('Error fetching group:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Group not found' });
    }

    const group = results[0];
    const messagesQuery = `
      SELECT * FROM \`messages\` 
      WHERE group_id = ? AND parent_id IS NULL
    `;
    
    connection.query(messagesQuery, [groupId], (err, messages) => {
      if (err) {
        console.error('Error fetching messages:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (messages.length === 0) {
        return res.json({ ...group, messages: [] }); // Return empty messages array if no messages
      }

      const messageIds = messages.map(message => message.id);
      const repliesQuery = `
        SELECT * FROM \`messages\` 
        WHERE parent_id IN (?)
      `;
      
      connection.query(repliesQuery, [messageIds], (err, replies) => {
        if (err) {
          console.error('Error fetching replies:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }

        const messagesWithReplies = messages.map(message => ({
          ...message,
          replies: replies.filter(reply => reply.parent_id === message.id)
        }));

        res.json({ ...group, messages: messagesWithReplies });
      });
    });
  });
});

app.post('/api/groups/messages/send/:id', async (req, res) => {
  const groupId = req.params.id;
  const { content, type, parentId = null } = req.body;
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from header

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
      const userId = await getUserIdFromToken(token);
      if (!userId) {
          return res.status(401).json({ error: 'Invalid token' });
      }

      const query = `INSERT INTO messages (group_id, content, sender, type, parent_id) VALUES (?, ?, ?, ?, ?)`;
      connection.query(query, [groupId, content, userId, type, parentId], (err, results) => {
          if (err) {
              console.error('Error inserting message:', err);
              return res.status(500).json({ error: 'Error sending message' });
          }

          res.status(200).json({ success: 'Message sent successfully' });
      });
  } catch (error) {
      console.error('Error fetching user ID:', error);
      res.status(401).json({ error: 'Unauthorized' }); // Unauthorized
  }
});

app.post('/shareFlashCard', async (req, res) => {
  const { id, groupId } = req.body; // Flashcard ID and Group ID
  const token = req.headers.authorization.split(' ')[1]; // Extract token from header

  try {
    // Extract user ID from token
    const senderId = await getUserIdFromToken(token);

    // Step 1: Insert message into the messages table
    const query = 'INSERT INTO messages (sender, group_id, type, content) VALUES (?, ?, ?, ?)';
    connection.query(query, [senderId, groupId, 'flashcard', id], (err, results) => {
      if (err) {
        console.error('Error inserting message:', err);
        return res.status(500).send('Error sharing flashcard');
      }

      // Step 2: Update Points
      const pointsQuery = 'SELECT * FROM user_points WHERE user_id = ?';
      connection.query(pointsQuery, [senderId], (err, pointsResults) => {
        if (err) {
          console.error('Error fetching user points:', err);
          return res.status(500).send('Failed to update points.');
        }

        if (pointsResults.length > 0) {
          // If user exists, update points
          connection.query(
            'UPDATE user_points SET points = points + 2 WHERE user_id = ?',
            [senderId],
            (err) => {
              if (err) {
                console.error('Error updating points:', err);
                return res.status(500).send('Failed to update points.');
              }
              res.status(200).send('Flashcard shared successfully! Points updated.');
            }
          );
        } else {
          // If user does not exist, insert new record with 2 points
          connection.query(
            'INSERT INTO user_points (user_id, points) VALUES (?, ?)',
            [senderId, 2],
            (err) => {
              if (err) {
                console.error('Error inserting points:', err);
                return res.status(500).send('Failed to update points.');
              }
              res.status(200).send('Flashcard shared successfully! Points added.');
            }
          );
        }
      });
    });
  } catch (error) {
    console.error('Error sharing flashcard:', error);
    res.status(401).send('Failed to authenticate user');
  }
});


// Route to get user name by token
app.get('/api/user/details/:id', async (req, res) => {
  const token = req.headers.authorization.split(' ')[1]; // Extract token from header
  const user_id = req.params.id;

  if (!token) {
      return res.status(403).send('Token is required');
  }

  try {
      const userId = await getUserIdFromToken(token);
      connection.query('SELECT unique_id FROM users WHERE id = ?', [user_id], (err, results) => {
          if (err) {
              console.error('Error fetching user_name:', err);
              return res.status(500).send('Failed to fetch user name.');
          }

          if (results.length === 0) {
              return res.status(404).send('User not found.');
          }

          res.json({ user_name: results[0].unique_id });
      });
  } catch (err) {
      res.status(401).send(err.message);
  }
});

// Endpoint to get group member count
app.get('/group/member-count/:groupId', (req, res) => {
  const { groupId } = req.params;
  connection.query('SELECT COUNT(*) AS memberCount FROM user_groups WHERE group_id = ?', [groupId], (error, results) => {
      if (error) {
          console.error('Error fetching group member count:', error);
          return res.status(500).json({ error: 'Internal server error' });
      }
      res.json({ memberCount: results[0].memberCount });
  });
});

app.post('/invite/group/:groupId', (req, res) => {
  const { groupId } = req.params;
  const { phoneNumber } = req.body;

  console.log('Request received:', { groupId, phoneNumber }); // Log request details

  // Check if phoneNumber is provided
  if (!phoneNumber) {
    return res.status(400).json({ message: 'Phone number is required.' });
  }

  // Check if group exists and its privacy
  connection.query('SELECT is_public, user_id FROM `groups` WHERE id = ?', [groupId], (error, groupResults) => {
    if (error) {
      console.error('Database error while fetching group details:', error); // Log database error
      return res.status(500).json({ message: 'Database error.' });
    }

    const group = groupResults[0];
    if (!group) {
      return res.status(404).json({ message: 'Group not found.' });
    }

    // Check if the group is private and the requester is not an admin
    if (!group.is_public) {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({ message: 'Authorization token is missing.' });
      }

      getUserIdFromToken(token)
        .then(userId => {
          console.log('Private group invite attempt:', { userId, groupOwner: group.user_id }); // Log private group invite attempt

          if (userId !== group.user_id) {
            return res.status(403).json({ message: 'Only admin can invite members to a private group.' });
          }

          handleInvitation(groupId, phoneNumber, res);
        })
        .catch(err => {
          console.error('Error fetching user ID from token:', err); // Log error fetching user ID from token
          res.status(500).json({ message: 'Internal server error.' });
        });
    } else {
      handleInvitation(groupId, phoneNumber, res);
    }
  });
});

function handleInvitation(groupId, phoneNumber, res) {
  // Check if the phone number belongs to a registered user
  connection.query('SELECT id FROM users WHERE phone_number = ?', [phoneNumber], (error, userResults) => {
    if (error) {
      console.error('Database error while checking user existence:', error); // Log database error
      return res.status(500).json({ message: 'Database error.' });
    }

    const user = userResults[0];
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const userId = user.id;

    // Check if the user is already a member of the group
    connection.query('SELECT * FROM user_groups WHERE user_id = ? AND group_id = ?', [userId, groupId], (error, membershipResults) => {
      if (error) {
        console.error('Database error while checking group membership:', error); // Log database error
        return res.status(500).json({ message: 'Database error.' });
      }

      if (membershipResults.length > 0) {
        return res.status(400).json({ message: 'User is already a member of the group.' });
      }

      // Check if an active invitation already exists
      connection.query('SELECT * FROM group_request WHERE phone_number = ? AND group_id = ? AND active = 1', [phoneNumber, groupId], (error, invitationResults) => {
        if (error) {
          console.error('Database error while checking existing invitations:', error); // Log database error
          return res.status(500).json({ message: 'Database error.' });
        }

        if (invitationResults.length > 0) {
          return res.status(400).json({ message: 'Invitation already sent.' });
        }

        // Add the invitation request
        connection.query('INSERT INTO group_request (group_id, phone_number, active) VALUES (?, ?, ?)', [groupId, phoneNumber, '1'], (error) => {
          if (error) {
            console.error('Database error while inserting invitation request:', error); // Log database error
            return res.status(500).json({ message: 'Failed to add invitation request.' });
          }

          res.status(200).json({ message: 'Invitation sent successfully.' });
        });
      });
    });
  });
}

// Endpoint to get group members
app.get('/api/groups/members/:group_id', (req, res) => {
  const groupId = req.params.group_id;

  if (isNaN(groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
  }

  // Query to get user IDs from the group_members table
  const groupMembersQuery = `
      SELECT user_id
      FROM user_groups
      WHERE group_id = ?
  `;

  connection.query(groupMembersQuery, [groupId], (err, results) => {
      if (err) {
          console.error('Error fetching group members:', err);
          return res.status(500).json({ error: 'Internal server error' });
      }

      const userIds = results.map(row => row.user_id);

      if (userIds.length === 0) {
          return res.json({ members: [] });
      }

      // Query to get user names from the users table
      const usersQuery = `
          SELECT id, unique_id
          FROM users
          WHERE id IN (?)
      `;

      connection.query(usersQuery, [userIds], (err, results) => {
          if (err) {
              console.error('Error fetching user names:', err);
              return res.status(500).json({ error: 'Internal server error' });
          }

          res.json({ members: results });
      });
  });
});


// Fetch Invitations API
app.get('/api/invitations', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).send('Token required');

    getUserIdFromToken(token)
        .then(userId => {
            // Get user's phone number
            const getPhoneNumberQuery = 'SELECT phone_number FROM users WHERE id = ?';
            connection.query(getPhoneNumberQuery, [userId], (err, results) => {
                if (err) {
                    console.error('Error fetching phone number:', err);
                    return res.status(500).send('Error fetching phone number');
                }
                const phoneNumber = results[0]?.phone_number;

                if (!phoneNumber) return res.status(404).send('User not found');

                // Fetch active invitations
                const invitationsQuery = `
                    SELECT gr.group_id, g.name AS group_name
                    FROM group_request gr
                    JOIN \`groups\` g ON gr.group_id = g.id
                    WHERE gr.phone_number = ? AND gr.active = 1`;
                
                connection.query(invitationsQuery, [phoneNumber], (err, results) => {
                    if (err) {
                        console.error('Error fetching invitations:', err);
                        return res.status(500).send('Error fetching invitations');
                    }
                    res.json(results);
                });
            });
        })
        .catch(error => {
            console.error('Token authentication error:', error);
            res.status(500).send('Failed to authenticate token');
        });
});

// New API endpoint
app.post('/invitations/respond', async (req, res) => {
  console.log('Received request:', req.body);

  const { groupId, action } = req.body;
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    console.log('Token missing');
    return res.status(403).send('Token required');
  }

  if (!['accept', 'ignore'].includes(action)) {
    console.log('Invalid action:', action);
    return res.status(400).send('Invalid action');
  }

  try {
    const userId = await getUserIdFromToken(token);

    // Fetch phone number from users table
    const getUserPhoneNumberQuery = 'SELECT phone_number FROM users WHERE id = ?';
    connection.query(getUserPhoneNumberQuery, [userId], (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send('Database query error');
      }
      if (results.length === 0) {
        console.log('User not found');
        return res.status(404).send('User not found');
      }

      const phoneNumber = results[0].phone_number;

      console.log('User phone number:', phoneNumber);

      // Check if the invitation exists
      const checkInvitationQuery = 'SELECT * FROM group_request WHERE phone_number = ? AND group_id = ? AND active = 1';
      connection.query(checkInvitationQuery, [phoneNumber, groupId], (err, results) => {
        if (err) {
          console.error('Database query error:', err);
          return res.status(500).send('Database query error');
        }
        if (results.length === 0) {
          console.log('Invitation not found');
          return res.status(404).send('Invitation not found');
        }

        if (action === 'accept') {
          const insertMembershipQuery = 'INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)';
          connection.query(insertMembershipQuery, [userId, groupId], (err) => {
            if (err) {
              console.error('Error inserting membership:', err);
              return res.status(500).send('Error inserting membership');
            }

            const updateInvitationQuery = 'UPDATE group_request SET active = 0, status = "accepted" WHERE phone_number = ? AND group_id = ?';
            connection.query(updateInvitationQuery, [phoneNumber, groupId], (err) => {
              if (err) {
                console.error('Error updating invitation:', err);
                return res.status(500).send('Error updating invitation');
              }
              console.log('Invitation accepted');
              res.send('Invitation accepted');
            });
          });
        } else if (action === 'ignore') {
          const updateInvitationQuery = 'UPDATE group_request SET active = 0, status = "rejected" WHERE phone_number = ? AND group_id = ?';
          connection.query(updateInvitationQuery, [phoneNumber, groupId], (err) => {
            if (err) {
              console.error('Error updating invitation:', err);
              return res.status(500).send('Error updating invitation');
            }
            console.log('Invitation ignored');
            res.send('Invitation ignored');
          });
        }
      });
    });
  } catch (err) {
    console.error('Failed to authenticate token:', err);
    res.status(500).send('Failed to authenticate token');
  }
});
const checkMembership = (userId, groupId, callback) => {
  // Fetch membership from the database
  connection.query('SELECT * FROM user_groups WHERE user_id = ? AND group_id = ?', [userId, groupId], (error, results) => {
      if (error) {
          console.error('Database query error:', error);
          return callback(error, null);
      }
      callback(null, results);
  });
};

// Routes
app.post('/api/checkUserMembership', async (req, res) => {
  const { token, groupId } = req.body;
  
  try {
      const userId = await getUserIdFromToken(token);
      
      if (!userId) {
          return res.status(401).json({ isMember: false });
      }

      checkMembership(userId, groupId, (error, membership) => {
          if (error) {
              return res.status(500).json({ message: 'Error checking membership' });
          }
          res.json({ isMember: membership.length > 0 });
      });

  } catch (error) {
      res.status(500).json({ message: 'Error checking membership' });
  }
});


// Create a new quiz
app.post('/createQuiz', async (req, res) => {
  const { token, title, description, questions } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    // Step 1: Insert the quiz
    const [result] = await connection.promise().query('INSERT INTO quizzes (title, description, creator_id) VALUES (?, ?, ?)', [title, description, userId]);
    const quizId = result.insertId;

    // Step 2: Insert questions and answers
    for (const question of questions) {
      const [questionResult] = await connection.promise().query('INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)', [quizId, question.text]);
      const questionId = questionResult.insertId;

      for (const answer of question.answers) {
        await connection.promise().query('INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)', [questionId, answer.text, answer.is_correct]);
      }
    }

    // Step 3: Update Points
    const pointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';
    const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

    const currentTime = new Date();
    const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000); // Subtract 5 minutes
    let pointsToAdd = 10; // Default points to add

    if (pointsResults.length > 0) {
      // If user exists, check updated_at timestamp
      const lastUpdated = new Date(pointsResults[0].updated_at);
      if (lastUpdated > fiveMinutesAgo) {
        // If last update was less than 5 minutes ago, add fewer points
        pointsToAdd = 10; // Or any number you choose
      }

      // Update points and set the updated_at timestamp
      await connection.promise().query(
        'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
        [pointsToAdd, currentTime, userId]
      );
    } else {
      // If user does not exist, insert new record with the points
      await connection.promise().query(
        'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
        [userId, pointsToAdd, currentTime]
      );
    }

    res.json({ message: 'Quiz created successfully', quizId });
  } catch (error) {
    console.error('Error creating quiz:', error);
    res.status(500).json({ message: 'Error creating quiz' });
  }
});

// Get quiz details including correct and incorrect answers
app.get('/quiz/answers/:quizId', async (req, res) => {
  const { quizId } = req.params;

  try {
    // Fetch quiz title and description
    const [quizResults] = await connection.promise().query(
      'SELECT title, description FROM quizzes WHERE id = ?',
      [quizId]
    );

    if (quizResults.length === 0) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    const quiz = quizResults[0];

    // Fetch questions, their answers, and explanations for this quiz
    const [questionsResults] = await connection.promise().query(
      `SELECT q.id AS question_id, q.question_text, 
              a.id AS answer_id, a.answer_text, a.is_correct, 
              ae.explanation 
       FROM questions q
       LEFT JOIN answers a ON q.id = a.question_id
       LEFT JOIN answer_explanations ae ON q.id = ae.question_id AND a.answer_text = ae.answer_text
       WHERE q.quiz_id = ?`,
      [quizId]
    );

    // Organize data into a structured format
    const questions = {};
    questionsResults.forEach((row) => {
      const questionId = row.question_id;
      if (!questions[questionId]) {
        questions[questionId] = {
          question_text: row.question_text,
          answers: []
        };
      }
      questions[questionId].answers.push({
        answer_text: row.answer_text,
        is_correct: row.is_correct === 1, // Convert to a boolean
        explanation: row.explanation // Include explanation
      });
    });

    // Convert the questions object into an array format
    quiz.questions = Object.values(questions);

    res.json(quiz);
  } catch (error) {
    console.error('Error fetching quiz answers:', error);
    res.status(500).json({ message: 'Error fetching quiz answers' });
  }
});


app.post('/api/quiz/generate', async (req, res) => {
  const { subject, topic, token } = req.body;

  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);

    // Step 2: Define a refined prompt to ensure proper JSON formatting
    const prompt = `
      Generate a valid JSON array of 15 multiple-choice questions for the following:
      - Subject: ${subject}
      - Topic: ${topic}

      Each question must strictly follow this format:
      [
        {
          "question": "string", // The question text
          "options": ["string", "string", "string", "string"], // An array of 4 options
          "correct_answer": "string" // The correct option text (must match one of the options)
        }
      ]

      Rules:
      1. Return only the JSON array without any explanations, comments, or markdown.
      2. The "question" field can include alphanumeric characters and basic punctuation.
      3. Each "options" array must have exactly 4 unique strings.
      4. Ensure the JSON is properly formatted and parsable without errors.
    `.trim();

    console.log('Generating quiz with refined prompt:', prompt);

    // Step 3: Function to handle quiz generation with retry logic
    const generateQuizWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          // Send the prompt to the AI model
          const chat = model.startChat({
            history: [
              { role: 'user', parts: [{ text: 'Hello' }] },
              { role: 'model', parts: [{ text: 'I can help generate quizzes for your study!' }] },
            ],
          });

          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          // Step 4: Sanitize the response to ensure it is valid JSON
          const sanitizedResponse = rawResponse
            .replace(/```(?:json)?/g, '') // Remove markdown code blocks (e.g., ```json)
            .trim();

          let quizQuestions;
          try {
            quizQuestions = JSON.parse(sanitizedResponse);
          } catch (parseError) {
            console.error('Failed to parse JSON:', parseError, 'Raw response:', sanitizedResponse);
            throw new Error('Invalid JSON response from the AI model');
          }

          // If we successfully parsed the JSON, return the quiz questions
          return quizQuestions;
        } catch (error) {
          attempts++;
          console.log(`Attempt ${attempts} failed, retrying...`);

          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate quiz after multiple attempts');
          }

          // Delay before retrying
          await delay(2000); // Delay for 2 seconds before the next attempt
        }
      }
    };

    // Step 5: Try generating the quiz with retries
    const quizQuestions = await generateQuizWithRetry();

    // Step 6: Insert quiz details into the database
    const title = `${subject} - ${topic} Quiz`;
    const description = `Quiz on ${subject} - ${topic}`;
    const [quizResult] = await connection.promise().query(
      'INSERT INTO quizzes (title, description, creator_id, is_ai) VALUES (?, ?, ?, ?)',
      [title, description, userId, 1] // Insert 1 for is_ai to indicate AI-generated quiz
    );
    const quizId = quizResult.insertId;

    // Step 7: Insert questions and their options into the database
    for (const question of quizQuestions) {
      const [questionResult] = await connection.promise().query(
        'INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)',
        [quizId, question.question]
      );
      const questionId = questionResult.insertId;

      for (const option of question.options) {
        const isCorrect = option === question.correct_answer;
        await connection.promise().query(
          'INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)',
          [questionId, option, isCorrect]
        );
      }
    }

    // Step 8: Return the generated quiz details
    res.json({ message: 'Quiz generated successfully', quizId });
  } catch (error) {
    console.error('Error generating quiz:', error);
    res.status(500).json({ error: 'Error generating quiz' });
  }
});

// API endpoint to fetch the number of flashcards created from AI
app.get("/api/quizzes/count/ai-premium", async (req, res) => {
  try {
    const token = req.headers.authorization; // Extract token from the Authorization header
    
    if (!token) {
      return res.status(400).json({ error: "Token is required" });
    }

    // Extract user_id from token
    const userId = await getUserIdFromToken(token);

    // Get the count of flashcards created from PDFs by the user
    const queryStr = `
      SELECT COUNT(*) AS QuizzesCount
      FROM quizzes
      WHERE creator_id = ? AND is_ai = 1 AND DATE(created_at) = CURDATE()
    `;

    connection.query(queryStr, [userId], (err, result) => {
      if (err) {
        console.error("Error fetching flashcards count:", err);
        return res.status(500).json({ error: "Something went wrong!" });
      }
      const QuizzesCount = result[0].QuizzesCount;
      res.json({ QuizzesCount });
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});

// Get all quizzes for a user
app.post('/getUserQuizzes', async (req, res) => {
  const { token } = req.body;

  try {
      const userId = await getUserIdFromToken(token);
      if (!userId) return res.status(401).json({ message: 'Unauthorized' });

      const [quizzes] = await connection.promise().query('SELECT * FROM quizzes WHERE creator_id = ?', [userId]);
      res.json(quizzes);
  } catch (error) {
      console.error('Error fetching quizzes:', error);
      res.status(500).json({ message: 'Error fetching quizzes' });
  }
});

// Get a single quiz by ID
app.get('/getQuiz/:id', async (req, res) => {
  const { id } = req.params;

  try {
      const [quiz] = await connection.promise().query('SELECT * FROM quizzes WHERE id = ?', [id]);
      const [questions] = await connection.promise().query('SELECT * FROM questions WHERE quiz_id = ?', [id]);

      for (const question of questions) {
          const [answers] = await connection.promise().query('SELECT * FROM answers WHERE question_id = ?', [question.id]);
          question.answers = answers;
      }

      res.json({ quiz: quiz[0], questions });
  } catch (error) {
      console.error('Error fetching quiz:', error);
      res.status(500).json({ message: 'Error fetching quiz' });
  }
});



app.post('/submitQuiz', async (req, res) => {
  const { token, quizId, answers } = req.body;

  // Input validation
  if (!token || typeof token !== 'string' || !quizId || typeof quizId !== 'number' || !Array.isArray(answers)) {
    console.error('Invalid input data:', req.body);
    return res.status(400).json({ message: 'Invalid input data' });
  }

  try {
    const userId = await getUserIdFromToken(token);
    let correctCount = 0;
    const correctAnswers = {};

    // Step 1: Check answers and collect correct answers
    for (const answer of answers) {
      if (typeof answer.answerId !== 'number' || typeof answer.questionId !== 'number') {
        console.error('Invalid answer format:', answer);
        return res.status(400).json({ message: 'Invalid answer format' });
      }

      const [result] = await connection.promise().query(
        'SELECT * FROM answers WHERE question_id = ? AND is_correct = TRUE',
        [answer.questionId]
      );

      if (result.length) {
        // Add correct answer to the correctAnswers object
        correctAnswers[answer.questionId] = {
          id: result[0].id,
          text: result[0].answer_text,
        };

        if (result[0].id === answer.answerId) correctCount++;
      }
    }

    // Step 2: Get total questions
    const [questions] = await connection.promise().query(
      'SELECT COUNT(*) AS count FROM questions WHERE quiz_id = ?',
      [quizId]
    );

    const totalQuestions = questions[0].count;

    if (totalQuestions === 0) {
      return res.status(400).json({ message: 'No questions found for this quiz' });
    }

    const score = (correctCount / totalQuestions) * 100;

    // Step 3: Save score to user_quizzes
    await connection.promise().query(
      'INSERT INTO user_quizzes (user_id, quiz_id, score) VALUES (?, ?, ?)',
      [userId, quizId, score]
    );

    // Step 4: Update Points
    const pointsQuery = 'SELECT * FROM user_points WHERE user_id = ?';
    const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

    if (pointsResults.length > 0) {
      // If user exists, update points
      await connection.promise().query('UPDATE user_points SET points = points + 15 WHERE user_id = ?', [userId]);
    } else {
      // If user does not exist, insert new record with 15 points
      await connection.promise().query('INSERT INTO user_points (user_id, points) VALUES (?, ?)', [userId, 15]);
    }

    res.json({ score, correctAnswers });

  } catch (error) {
    console.error('Error submitting quiz:', error.message);
    res.status(500).json({ message: 'Error submitting quiz' });
  }
});

app.post('/shareQuiz', async (req, res) => {
  const { quizId, groupId } = req.body; // Quiz ID and Group ID
  const token = req.headers.authorization.split(' ')[1]; // Extract token from header

  try {
    // Extract user ID from token
    const senderId = await getUserIdFromToken(token);

    // Insert message into the messages table
    const query = 'INSERT INTO messages (sender, group_id, type, content) VALUES (?, ?, ?, ?)';
    await connection.promise().query(query, [senderId, groupId, 'quiz', quizId]);

    // Step 1: Update Points
    const pointsQuery = 'SELECT * FROM user_points WHERE user_id = ?';
    const [pointsResults] = await connection.promise().query(pointsQuery, [senderId]);

    if (pointsResults.length > 0) {
      // If user exists, update points
      await connection.promise().query('UPDATE user_points SET points = points + 6 WHERE user_id = ?', [senderId]);
    } else {
      // If user does not exist, insert new record with 6 points
      await connection.promise().query('INSERT INTO user_points (user_id, points) VALUES (?, ?)', [senderId, 6]);
    }

    res.status(200).send('Quiz shared successfully');
  } catch (error) {
    console.error('Error sharing quiz:', error);
    res.status(401).send('Failed to authenticate user');
  }
});


app.post('/api/getUserResults', async (req, res) => {
  const token = req.body.token;

  try {
      // Wait for the promise to resolve
      const userId = await getUserIdFromToken(token);

      // Log the userId to ensure it's a valid value
      console.log('userId:', userId);

      const sql = `
          SELECT quizzes.title AS quizTitle, user_quizzes.score, user_quizzes.completed_at AS takenAt
          FROM user_quizzes
          JOIN quizzes ON user_quizzes.quiz_id = quizzes.id
          WHERE user_quizzes.user_id = ?
      `;

      // Execute the SQL query
      connection.query(sql, [userId], (err, results) => {
          if (err) {
              console.error('Error fetching user results:', err);
              return res.status(500).send('Server Error');
          }
          res.json(results);
      });
  } catch (error) {
      console.error('Error fetching user results:', error);
      res.status(500).send('Server Error');
  }
});

app.post('/api/getQuizResults', (req, res) => {
  const { token, quizId } = req.body;
  // Verify token logic here...

  const query = `
      SELECT uq.score, uq.completed_at, u.user_name AS user_name 
      FROM user_quizzes uq
      JOIN users u ON uq.user_id = u.id
      WHERE uq.quiz_id = ?
  `;

  connection.query(query, [quizId], (err, results) => {
      if (err) {
          console.error('Error fetching quiz results:', err);
          return res.status(500).send({ error: 'Error fetching quiz results' });
      }

      res.send(results);
  });
});

// Fetch events route
app.post('/api/fetchEvents', async (req, res) => {
  const { token } = req.body;
  try {
      const userId = await getUserIdFromToken(token);
      const sql = 'SELECT * FROM events WHERE user_id = ?';
      connection.query(sql, [userId], (err, result) => {
          if (err) return res.status(500).send(err);
          res.send(result);
      });
  } catch (error) {
      res.status(401).send(error.message);
  }
});

// Add event route
app.post('/api/addEvent', async (req, res) => {
  const { title, date, token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    // Step 1: Insert event
    const sql = 'INSERT INTO events (title, date, user_id) VALUES (?, ?, ?)';
    const [result] = await connection.promise().query(sql, [title, date, userId]);

    // Step 2: Update Points
    const pointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';
    const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

    const currentTime = new Date();
    const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000); // Subtract 5 minutes
    let pointsToAdd = 3; // Default points to add

    if (pointsResults.length > 0) {
      // If user exists, check updated_at timestamp
      const lastUpdated = new Date(pointsResults[0].updated_at);
      if (lastUpdated > fiveMinutesAgo) {
        // If last update was less than 5 minutes ago, add fewer points
        pointsToAdd = 3; // Or any number you choose
      }

      // Update points and set the updated_at timestamp
      await connection.promise().query(
        'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
        [pointsToAdd, currentTime, userId]
      );
    } else {
      // If user does not exist, insert new record with the points
      await connection.promise().query(
        'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
        [userId, pointsToAdd, currentTime]
      );
    }

    // Send response with event ID
    res.send({ id: result.insertId });
  } catch (error) {
    console.error('Error adding event:', error);
    res.status(500).send({ message: 'Error adding event' });
  }
});




// Remove Event
app.post('/api/events/remove', async (req, res) => {
  const { id, token } = req.body; // Assuming token-based authentication

  try {
    // Step 1: Get User ID from token
    const userId = await getUserIdFromToken(token);

    // Step 2: Delete the event
    connection.query('DELETE FROM events WHERE id = ? AND user_id = ?', [id, userId], async (err) => {
      if (err) {
        console.error('Error deleting event:', err);
        return res.status(500).json({ success: false, message: 'Error deleting event' });
      }

      // Step 3: Update Points
      const pointsQuery = 'SELECT * FROM user_points WHERE user_id = ?';
      const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

      if (pointsResults.length > 0) {
        // If user exists, update points
        await connection.promise().query('UPDATE user_points SET points = points + 1 WHERE user_id = ?', [userId]);
      } else {
        // If user does not exist, insert new record with 1 point
        await connection.promise().query('INSERT INTO user_points (user_id, points) VALUES (?, ?)', [userId, 1]);
      }

      res.json({ success: true });
    });
  } catch (error) {
    console.error('Error in remove event:', error);
    res.status(401).json({ success: false, message: 'Unauthorized' });
  }
});


// Update Event
app.post('/api/events/update', (req, res) => {
  const { id, title, date, token } = req.body; // Assuming token-based authentication
  const query = 'UPDATE events SET title = ?, date = ? WHERE id = ?';
  connection.query(query, [title, date, id], err => {
      if (err) throw err;
      res.json({ success: true });
  });
});


app.post('/api/fetchUserActivities', async (req, res) => {
  const { token } = req.body;
  try {
      const userId = await getUserIdFromToken(token);
      const sql = 'SELECT * FROM user_quizzes WHERE user_id = ?';
      connection.query(sql, [userId], (err, result) => {
          if (err) return res.status(500).send(err);
          res.send(result);
      });
  } catch (error) {
      res.status(401).send(error.message);
  }
});

// Improved API endpoint for validating token session
app.post('/api/validate-token-session', (req, res) => {
  const { token } = req.body;

  // Check if token is provided
  if (!token) {
    return res.status(400).json({ valid: false, message: 'Token is required' });
  }

  const query = 'SELECT * FROM session WHERE jwt = ?';
  connection.query(query, [token], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ valid: false, message: 'Internal server error. Please try again later.' });
    }

    // Token not found in the database
    if (results.length === 0) {
      console.log('Token not found or session expired:', token);
      return res.status(401).json({ valid: false, message: 'Invalid token or session expired' });
    }

    return res.status(200).json({ valid: true });
  });
});

// Route for the app download (Android)
app.get('/download/android', (req, res) => {
  const file = path.join(__dirname, 'public', 'app', 'Edusify.apk');
  
  console.log('Android app download requested:', req.ip); // Log the request IP address
  res.download(file, (err) => {
    if (err) {
      console.error('Error downloading Android app:', err);
      res.status(500).send('Error downloading file');
    } else {

    }
  });
});

app.get('/download/test/route', (req, res) => {
  res.redirect('https://edusify.vercel.app/'); // Redirect to the specified URL
});

// Route for iOS download
app.get('/download/ios', (req, res) => {
  const file = path.join(__dirname, 'public', 'app', 'Educify.shortcut'); // Adjust path as necessary
  
  console.log('iOS app download requested:', req.ip); // Log the request IP address
  res.download(file, (err) => {
    if (err) {
      console.error('Error downloading iOS app:', err);
      res.status(500).send('Error downloading file');
    } else {
      console.log('iOS app download successful:', req.ip); // Log successful download
    }
  });
});


// Endpoint to check token
app.post('/api/session-check', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token is required.' });
  }

  const query = 'SELECT * FROM session WHERE jwt = ?';
  connection.query(query, [token], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }

    if (results.length > 0) {
      res.json({ exists: true });
    } else {
      res.json({ exists: false });
    }
  });
});

const CLIENT_ID = '0aac6cb1ec104103a5e2e5d6f9b490e7';
const CLIENT_SECRET = '4e2d9a5a3be9406c970cf3f6cb78b7a3';
const REDIRECT_URI = 'http://localhost:8080/callback/spotify';
const FRONTEND_REDIRECT_URI = 'http://localhost:3000/music'; // Your React app's page

// Spotify Auth Endpoint
app.get('/login/spotify', (req, res) => {
  const authUrl = `https://accounts.spotify.com/authorize?response_type=code&client_id=${CLIENT_ID}&scope=streaming%20user-library-read%20user-read-playback-state%20user-modify-playback-state&redirect_uri=${REDIRECT_URI}`;
  res.redirect(authUrl);
});

// Callback route to get access token
app.get('/callback/spotify', async (req, res) => {
  const code = req.query.code;
  try {
    const tokenResponse = await axios.post(
      'https://accounts.spotify.com/api/token',
      null,
      {
        params: {
          code,
          redirect_uri: REDIRECT_URI,
          grant_type: 'authorization_code',
        },
        headers: {
          Authorization: `Basic ${Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')}`,
        },
      }
    );

    const access_token = tokenResponse.data.access_token;

    // Redirect back to the frontend with the access token as a query parameter
    res.redirect(`${FRONTEND_REDIRECT_URI}?access_token=${access_token}`);
  } catch (error) {
    console.error('Error during token exchange', error);
    res.status(500).send('Failed to authenticate with Spotify');
  }
});

app.post('/api/profile/user', async (req, res) => {
  try {
    const token = req.body.token;

    if (!token) {
      return res.status(400).send('No token provided');
    }

    // Get user ID from token
    const userId = await getUserIdFromToken(token);

    // Fetch user profile data
    connection.query('SELECT * FROM users WHERE id = ?', [userId], (error, results) => {
      if (error) return res.status(500).send(error);
      if (results.length === 0) return res.status(404).send('User not found');
      res.json(results[0]);
    });
  } catch (error) {
    res.status(401).send(error);
  }
});


app.get('/api/eduscribes', async (req, res) => {
  try {
    // Extract token from request headers
    const token = req.headers['authorization'];
    if (!token) {
      return res.status(401).json({ message: 'Token required' });
    }

    // Function to get user ID from token (implement this according to your authentication logic)
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ message: 'Invalid token or user ID not found' });
    }

    // Get tab filter from query parameter
    const { tab } = req.query;

    let sql;
    let params = [userId];

    if (tab === 'Following') {
      // Query to get user IDs that the current user is following
      const followingQuery = 'SELECT following_id FROM followers WHERE follower_id = ?';
      const followingResults = await query(followingQuery, [userId]);
      const followingIds = followingResults.map(f => f.following_id);

      if (followingIds.length === 0) {
        // No following users
        return res.json([]);
      }

      // Query to fetch eduscribes for the users the current user is following
      sql = `
        SELECT e.id, e.content, e.image, e.created_at, u.id AS user_id, u.user_name, u.avatar,
               (SELECT COUNT(*) FROM comments c WHERE c.eduscribe_id = e.id) AS commentsCount,
               (SELECT COUNT(*) FROM likes l WHERE l.eduscribe_id = e.id) AS likesCount,
               (SELECT COUNT(*) FROM likes l WHERE l.eduscribe_id = e.id AND l.user_id = ?) AS isLiked
        FROM eduscribes e
        JOIN users u ON e.user_id = u.id
        WHERE e.user_id IN (?)
        GROUP BY e.id, u.id
        ORDER BY e.created_at DESC
      `;
      params.push(followingIds);
    } else {
      // Default to fetching all eduscribes for "For You" tab
      sql = `
        SELECT e.id, e.content, e.image, e.created_at, u.id AS user_id, u.user_name, u.avatar,
               (SELECT COUNT(*) FROM comments c WHERE c.eduscribe_id = e.id) AS commentsCount,
               (SELECT COUNT(*) FROM likes l WHERE l.eduscribe_id = e.id) AS likesCount,
               (SELECT COUNT(*) FROM likes l WHERE l.eduscribe_id = e.id AND l.user_id = ?) AS isLiked
        FROM eduscribes e
        JOIN users u ON e.user_id = u.id
        GROUP BY e.id, u.id
        ORDER BY e.created_at DESC
      `;
    }

    // Execute query
    const results = await query(sql, params);
    res.json(results);
  } catch (error) {
    console.error('Error fetching eduscribes:', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Add Eduscribe endpoint
app.post('/api/add/eduscribes', upload.single('image'), async (req, res) => {
  const { question, token } = req.body;
  const imageName = req.file ? req.file.filename : null;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    const sql = 'INSERT INTO eduscribes (content, user_id, image) VALUES (?, ?, ?)';
    const [result] = await connection.promise().query(sql, [question, userId, imageName]);

    // Step 2: Update Points
    const pointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';
    const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

    const currentTime = new Date();
    const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000); // Subtract 5 minutes
    let pointsToAdd = 10; // Default points to add

    if (pointsResults.length > 0) {
      // If user exists, check updated_at timestamp
      const lastUpdated = new Date(pointsResults[0].updated_at);
      if (lastUpdated > fiveMinutesAgo) {
        // If last update was less than 5 minutes ago, add fewer points
        pointsToAdd = 3; // Adjust this value as needed
      }

      // Update points and set the updated_at timestamp
      await connection.promise().query(
        'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
        [pointsToAdd, currentTime, userId]
      );
    } else {
      // If user does not exist, insert new record with the points
      await connection.promise().query(
        'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
        [userId, pointsToAdd, currentTime]
      );
    }

    res.status(200).json({ message: 'Eduscribe submitted successfully!', id: result.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// API endpoint to like/unlike an eduscribe
app.post('/api/eduscribes/like/:id', async (req, res) => {
  const { id } = req.params;
  const { token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    
    if (!userId) {
      return res.status(400).send({ message: 'Invalid token or user ID not found' });
    }

    // Check if user already liked this eduscribe
    const checkSql = 'SELECT * FROM likes WHERE eduscribe_id = ? AND user_id = ?';
    connection.query(checkSql, [id, userId], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).send({ message: 'Database error' });
      }

      if (results.length > 0) {
        // Unlike if already liked
        const deleteSql = 'DELETE FROM likes WHERE eduscribe_id = ? AND user_id = ?';
        connection.query(deleteSql, [id, userId], (err) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ message: 'Database error' });
          }
          res.send({ message: 'Unliked successfully' });
        });
      } else {
        // Like if not yet liked
        const insertSql = 'INSERT INTO likes (eduscribe_id, user_id) VALUES (?, ?)';
        connection.query(insertSql, [id, userId], (err) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ message: 'Database error' });
          }
          res.send({ message: 'Liked successfully' });
        });
      }
    });
  } catch (error) {
    console.error('Error liking eduscribe:', error.message);
    res.status(500).send({ message: 'Internal Server Error' });
  }
});

// API endpoint to comment on an eduscribe
app.post('/api/eduscribes/comment/add/:id', async (req, res) => {
  const { id } = req.params;
  const { token, comment } = req.body;

  try {
    const userId = await getUserIdFromToken(token);

    if (!userId) {
      return res.status(400).send({ message: 'Invalid token or user ID not found' });
    }

    const sql = 'INSERT INTO comments (eduscribe_id, user_id, content) VALUES (?, ?, ?)';
    connection.query(sql, [id, userId, comment], (err) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).send({ message: 'Database error' });
      }
      res.send({ message: 'Comment added successfully' });
    });
  } catch (error) {
    console.error('Error commenting on eduscribe:', error.message);
    res.status(500).send({ message: 'Internal Server Error' });
  }
});

app.get('/api/eduscribes/comments/:id', async (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT comments.id, comments.content, comments.created_at, users.avatar, users.user_name 
    FROM comments 
    JOIN users ON comments.user_id = users.id 
    WHERE comments.eduscribe_id = ?
  `;
  
  connection.query(sql, [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send({ message: 'Database error' });
    }
    res.send(results);
  });
});

// Route to get user profile, including followers and following counts
app.get('/api/profile/view/guest/:user_id', (req, res) => {
  const userId = req.params.user_id;
  const profileQuery = 'SELECT * FROM users WHERE id = ?';
  const followersQuery = 'SELECT COUNT(*) AS count FROM followers WHERE following_id = ?';
  const followingQuery = 'SELECT COUNT(*) AS count FROM followers WHERE follower_id = ?';

  connection.query(profileQuery, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching user profile:', err);
      return res.status(500).json({ error: 'Failed to fetch user profile' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const profile = results[0];

    connection.query(followersQuery, [userId], (err, followersResults) => {
      if (err) {
        console.error('Error fetching followers count:', err);
        return res.status(500).json({ error: 'Failed to fetch followers count' });
      }

      connection.query(followingQuery, [userId], (err, followingResults) => {
        if (err) {
          console.error('Error fetching following count:', err);
          return res.status(500).json({ error: 'Failed to fetch following count' });
        }

        res.json({
          ...profile,
          followersCount: followersResults[0].count,
          followingCount: followingResults[0].count,
        });
      });
    });
  });
});

// Route to get followers
app.get('/api/profile/followers/:user_id', (req, res) => {
  const userId = req.params.user_id;
  const query = 'SELECT u.unique_id, u.avatar, u.id FROM followers f JOIN users u ON f.follower_id = u.id WHERE f.following_id = ?';
  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching followers:', err);
      return res.status(500).json({ error: 'Failed to fetch followers' });
    }
    res.json(results);
  });
});

// Route to get following users
app.get('/api/profile/following/:user_id', (req, res) => {
  const userId = req.params.user_id;
  const query = 'SELECT u.unique_id, u.avatar, u.id FROM followers f JOIN users u ON f.following_id = u.id WHERE f.follower_id = ?';
  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching following users:', err);
      return res.status(500).json({ error: 'Failed to fetch following users' });
    }
    res.json(results);
  });
});

app.get('/api/user/profile/items/:id', async (req, res) => {
  const userId = req.params.id;
  
  try {
    const [flashcards] = await connection.promise().query(`SELECT * FROM flashcards WHERE user_id = ? AND is_public = 'true'`, [userId]);
    const [quizzes] = await connection.promise().query('SELECT * FROM quizzes WHERE creator_id = ?', [userId]);
    const [eduscribes] = await connection.promise().query('SELECT * FROM eduscribes WHERE user_id = ?', [userId]);

    res.json({ flashcards, quizzes, eduscribes });
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});




// Follow endpoint
app.post('/api/follow', async (req, res) => {
  console.log('Received follow request');
  const { id, token } = req.body; // Profile ID to follow and token

  if (!id || !token) {
    console.log('Missing ID or token');
    return res.status(400).json({ message: 'ID and token are required' });
  }

  try {
    const userId = await getUserIdFromToken(token);

    const rows = await query('SELECT * FROM followers WHERE follower_id = ? AND following_id = ?', [userId, id]);

    if (rows.length > 0) {
      // Already following
      console.log('Already following');
      return res.status(200).json({ message: 'Already following' });
    }

    // Insert follow record
    const result = await query('INSERT INTO followers (follower_id, following_id) VALUES (?, ?)', [userId, id]);
    console.log('Followed successfully:', result);
    res.status(200).json({ message: 'Followed successfully', result });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Failed to follow user' });
  }
});

// Unfollow endpoint
app.post('/api/unfollow', async (req, res) => {
  console.log('Received unfollow request');
  const { id, token } = req.body; // Profile ID to unfollow and token

  if (!id || !token) {
    console.log('Missing ID or token');
    return res.status(400).json({ message: 'ID and token are required' });
  }

  try {
    const userId = await getUserIdFromToken(token);

    // Delete follow record
    const result = await query('DELETE FROM followers WHERE follower_id = ? AND following_id = ?', [userId, id]);
    console.log('Unfollowed successfully:', result);
    res.status(200).json({ message: 'Unfollowed successfully', result });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Failed to unfollow user' });
  }
});

// Check if following endpoint
app.post('/api/isFollowing', async (req, res) => {
  console.log('Received isFollowing request');
  const { id, token } = req.body; // Profile ID to check and token

  if (!id || !token) {
    console.log('Missing ID or token');
    return res.status(400).json({ message: 'ID and token are required' });
  }

  try {
    const userId = await getUserIdFromToken(token);

    // Check if following
    const rows = await query('SELECT * FROM followers WHERE follower_id = ? AND following_id = ?', [userId, id]);
    if (rows.length > 0) {
      console.log('Following');
      res.status(200).json({ following: true });
    } else {
      console.log('Not following');
      res.status(200).json({ following: false });
    }
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Failed to check follow status' });
  }
});


// Endpoint to solve math queries with Gemini AI
app.post('/api/solve-math', async (req, res) => {
  const { query } = req.body; // Use the query from the request body

  try {
      const result = await model.generateContent(query); // Send the query as the prompt
      res.json({ response: result.response.text() }); // Return the response
      console.log("Ai responded!", query);
  } catch (error) {
      console.error("Error generating content:", error, query);
      res.status(500).json({ error: 'Failed to generate content' });
  }
});

// Wolfram Alpha Science Query Endpoint with Fallback
app.get('/wolfram/science', async (req, res) => {
  const query = req.query.input;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter is required' });
  }

  try {
    // Attempt to fetch from Wolfram Alpha
    const wolframResponse = await axios.get('https://api.wolframalpha.com/v2/query', {
      params: {
        input: query,
        format: 'plaintext,image',
        output: 'JSON',
        appid: 'XH7LLE-WVTQHYEG2U'
      }
    });

    const result = wolframResponse.data.queryresult;
    if (result) {
      return res.json(result);
    } else {
      // If no result, fallback to DuckDuckGo and Wikipedia
      const fallbackData = await getFallbackData(query);
      if (fallbackData) {
        return res.json(fallbackData);
      } else {
        return res.status(404).json({ error: 'No results found' });
      }
    }
  } catch (error) {
    console.error('Error fetching data from Wolfram Alpha:', error.message);
    // Try fallback even if Wolfram Alpha request fails
    try {
      const fallbackData = await getFallbackData(query);
      if (fallbackData) {
        return res.json(fallbackData);
      }
    } catch (fallbackError) {
      console.error('Error fetching fallback data:', fallbackError.message);
    }
    return res.status(500).json({ error: 'Error fetching data' });
  }
});

// Function for fallback data retrieval
async function getFallbackData(query) {
  try {
    // DuckDuckGo API request
    const duckduckgoResponse = await axios.get('https://api.duckduckgo.com/', {
      params: {
        q: query,
        format: 'json',
        pretty: 1
      }
    });

    if (duckduckgoResponse.data.AbstractText) {
      return [{ title: duckduckgoResponse.data.Heading, content: duckduckgoResponse.data.AbstractText }];
    }

    // Fallback to Wikipedia
    const wikiResponse = await axios.get('https://en.wikipedia.org/w/api.php', {
      params: {
        action: 'query',
        format: 'json',
        prop: 'extracts',
        titles: query,
        exintro: true,
        explaintext: true
      }
    });

    const pages = wikiResponse.data.query.pages;
    const page = Object.values(pages)[0];
    if (page.extract) {
      return [{ title: page.title, content: page.extract }];
    }

    return null;
  } catch (error) {
    console.error('Error fetching fallback data:', error.message);
    return null;
  }
}


app.get('/search', (req, res) => {
  const { query } = req.query;

  const sql = `SELECT * FROM users WHERE user_name LIKE ? OR unique_id LIKE ?`;
  const values = [`%${query}%`, `%${query}%`];

  connection.query(sql, values, (err, results) => {
      if (err) {
          console.error('Error executing query:', err);
          res.status(500).send('Server error');
      } else {
          res.json(results);
      }
  });
});


app.put('/user/update', upload.single('avatar'), (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  getUserIdFromToken(token).then(userId => {
    if (!userId) {
      return res.status(400).send('User ID is missing');
    }

    const { unique_id, user_name, bio, location, phone_number } = req.body;

    const query = `
      UPDATE users
      SET unique_id = ?, user_name = ?, bio = ?, location = ?, phone_number = ?
      WHERE id = ?
    `;

    connection.query(query, [unique_id, user_name, bio, location, phone_number, userId], (err, results) => {
      if (err) {
        console.error('Error updating profile:', err);
        return res.status(500).send('Error updating profile');
      }
      res.status(200).send('Profile updated successfully');
    });
  }).catch(err => {
    console.error('Error fetching user ID:', err);
    res.status(500).send('Internal server error');
  });
});

// API route to remove avatar and set default image
app.post('/api/remove-avatar', (req, res) => {
  const { unique_id } = req.body;
  const defaultAvatar = 'defPic.png'; // Default avatar image name

  if (!unique_id) {
    return res.status(400).json({ error: 'Unique ID is required' });
  }

  const query = 'UPDATE users SET avatar = ? WHERE unique_id = ?';
  connection.query(query, [defaultAvatar, unique_id], (err, result) => {
    if (err) {
      console.error('Error updating avatar:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.status(200).json({ message: 'Avatar removed and set to default image' });
  });
});

app.post('/api/commerce', async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Query parameter is required' });
  }

  try {
    console.log(`Received query: ${query}`); // Log the query

    // Wolfram Alpha API request
    const wolframResponse = await axios.get('https://api.wolframalpha.com/v2/query', {
      params: {
        input: query,
        appid: 'XH7LLE-QYT93AR839',
        format: 'plaintext',
        output: 'JSON'
      },
    });

    const wolframPods = wolframResponse.data.queryresult.pods;
    if (wolframPods) {
      const results = wolframPods.flatMap(pod => {
        return pod.subpods.map(subpod => {
          // Clean up the text
          const cleanedText = subpod.plaintext
            .replace(/^\d+\s*\|\s*\w+\s*\|\s*/, '') // Remove list numbering and labels
            .replace(/\s{2,}/g, ' ') // Replace multiple spaces with a single space
            .trim(); // Remove any leading or trailing whitespace

          return {
            title: pod.title,
            content: cleanedText
          };
        });
      });
      return res.json(results);
    } else {
      // Fallback API calls
      const fallbackData = await getFallbackData(query);
      if (fallbackData) {
        return res.json(fallbackData);
      } else {
        return res.status(404).json({ error: 'No results found' });
      }
    }
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Error fetching data' });
  }
});

async function getFallbackData(query) {
  try {
    // DuckDuckGo API request
    const duckduckgoResponse = await axios.get('https://api.duckduckgo.com/', {
      params: {
        q: query,
        format: 'json',
        pretty: 1
      }
    });

    if (duckduckgoResponse.data.AbstractText) {
      return [{
        title: duckduckgoResponse.data.Heading,
        content: duckduckgoResponse.data.AbstractText.replace(/\.\s+/g, '.\n') // Clean up sentences
      }];
    }

    // Fallback to Wikipedia if no other results are found
    const wikiResponse = await axios.get('https://en.wikipedia.org/w/api.php', {
      params: {
        action: 'query',
        format: 'json',
        prop: 'extracts',
        titles: query,
        exintro: true,
        explaintext: true
      }
    });

    const pages = wikiResponse.data.query.pages;
    const page = Object.values(pages)[0];
    if (page.extract) {
      return [{
        title: page.title,
        content: page.extract.replace(/\.\s+/g, '.\n') // Clean up sentences
      }];
    }

    return null;
  } catch (error) {
    console.error('Error fetching fallback data:', error);
    return null;
  }
}

const generateToken = () => crypto.randomBytes(20).toString('hex');

// Forgot Password Route
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { emailOrPhone } = req.body;
    const [userResults] = await connection.promise().query(
      'SELECT * FROM users WHERE email = ? OR phone_number = ?',
      [emailOrPhone, emailOrPhone]
    );

    if (userResults.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = userResults[0];
    const token = generateToken();
    const resetLink = `https://edusify.vercel.app/reset-password/${token}`;
    const expirationTime = new Date(Date.now() + 3600000);

    await connection.promise().query(
      'INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
      [user.email, token, expirationTime]
    );

    // Send the email in a non-blocking way
    const mailOptions = {
      to: user.email,
      from: 'edusyfy@gmail.com',
      subject: 'Password Reset Request',
      text: `Hi ${user.name || 'there'},\n\nWe received a request to reset your password. You can reset it by clicking on the link below:\n\n${resetLink}\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nYour Edusify Team`
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.log('Error sending email:', err);
        return res.status(500).json({ error: 'Error sending email' });
      }
      console.log('Email sent:', info.response);
      res.status(200).json({ message: 'Reset link sent' });
    });
  } catch (err) {
    console.error('Error in forgot password route:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Reset Password Route
app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body;

  // Validate token
  connection.query('SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()', [token], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });

    const email = results[0].email;
    const saltRounds = 10;

    // Hash the new password
    bcrypt.hash(password, saltRounds, (hashErr, hash) => {
      if (hashErr) return res.status(500).json({ error: 'Internal server error' });

      // Update the password in the database
      connection.query('UPDATE users SET password = ? WHERE email = ?', [hash, email], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        // Deactivate the token
        connection.query('DELETE FROM password_resets WHERE token = ?', [token], (err) => {
          if (err) return res.status(500).json({ error: 'Database error' });

          res.status(200).json({ message: 'Password successfully updated' });
        });
      });
    });
  });
});

app.post('/api/leave-group/:id', (req, res) => {
  const { id: groupId } = req.params;
  const token = req.headers.authorization.split(' ')[1];

  getUserIdFromToken(token)
    .then(userId => {
      connection.query('DELETE FROM user_groups WHERE user_id = ? AND group_id = ?', [userId, groupId], (error, result) => {
        if (error) {
          console.error(error);
          res.status(500).json({ error: 'Server error' });
        } else {
          if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Left group successfully' });
          } else {
            res.status(400).json({ error: 'Failed to leave group' });
          }
        }
      });
    })
    .catch(error => {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
    });
});




// Create Checkout Session
app.post('/api/create-checkout-session', (req, res) => {
  const { token } = req.body; // Token sent from the client

  // Retrieve userId from token
  getUserIdFromToken(token)
    .then(senderId => {
      return stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'INR',
            product_data: {
              name: 'Edusify Premium',
              description: 'Unlock premium features of Edusify!',
            },
            unit_amount: 11800, // Amount in paise (₹118.00)
          },
          quantity: 1,
        }],
        
        mode: 'payment',
        success_url: `${SUCCESS_URL}${senderId}`, // Redirect to backend success URL
        cancel_url: CANCEL_URL, // Redirect to backend cancel URL
      });
    })
    .then(session => {
      res.json({ url: session.url });
    })
    .catch(error => {
      console.error('Error creating checkout session:', error);
      res.status(500).send('Internal Server Error');
    });
});

const handlePaymentSuccess = (sessionId, senderId, callback) => {
  stripe.checkout.sessions.retrieve(sessionId)
    .then(session => {
      const currentDate = new Date();
      const expiryDate = new Date(currentDate);
      expiryDate.setDate(currentDate.getDate() + 30); // Set expiry date to 30 days from now

      const query = 'UPDATE users SET is_premium = 1, premium_expiry_date = ? WHERE id = ?';
      connection.query(query, [expiryDate, senderId], (err, result) => {
        if (err) {
          console.error('Error updating user subscription:', err);
          callback(err);
        } else {
          console.log('User subscription updated successfully');
          callback(null);
        }
      });
    })
    .catch(error => {
      console.error('Error handling payment success:', error);
      callback(error);
    });
};

// Success Endpoint
app.get('/success', (req, res) => {
  const sessionId = req.query.session_id;
  const senderId = req.query.sender_id;

  handlePaymentSuccess(sessionId, senderId, (err) => {
    if (err) {
      console.error('Error handling payment success:', err);
      res.redirect(`${FRONTEND_BASE_URL}/payment-success?success=false`);
    } else {
      res.redirect(`${FRONTEND_BASE_URL}/payment-success?success=true`);
    }
  });
});

// Cancel Endpoint
app.get('/cancel', (req, res) => {
  res.redirect(FRONTEND_BASE_URL); // Redirect to the frontend home or cancel page
});


// Function to remove expired premium subscriptions
const removeExpiredSubscriptions = () => {
  const currentDate = new Date();

  // Delete subscriptions where expiry_date has passed
  const deleteQuery = `
    DELETE FROM subscriptions 
    WHERE expiry_date < ?`;

  connection.query(deleteQuery, [currentDate], (err, results) => {
    if (err) {
      console.error('Error deleting expired subscriptions:', err);
    } else {
      console.log(`Deleted ${results.affectedRows} expired subscriptions.`);
    }
  });
};


// Schedule the cron job to run every day at 6:30 PM UTC (which is 12:00 AM IST)
cron.schedule('30 18 * * *', () => {
  console.log('Running cleanup for expired subscriptions...');
  removeExpiredSubscriptions();
});



// Example in Node.js with Express
app.post('/api/verifyPremium', (req, res) => {
  const { token } = req.body;

  getUserIdFromToken(token)
    .then(userId => {
      connection.query('SELECT is_premium FROM users WHERE id = ?', [userId], (error, results) => {
        if (error) {
          return res.status(500).json({ message: 'Error verifying premium status', error });
        }

        if (results.length > 0) {
          res.json({ is_premium: results[0].is_premium === 1 });
        } else {
          res.status(404).json({ message: 'User not found' });
        }
      });
    })
    .catch(error => {
      res.status(500).json({ message: 'Error verifying premium status', error });
    });
});


app.post('/getEduScribe/user/profile', (req, res) => {
  const { token } = req.body;

  getUserIdFromToken(token)
    .then(userId => {
      if (!userId) {
        return res.status(401).json({ message: 'Invalid token' });
      }

      return query('SELECT * FROM eduscribes WHERE user_id = ?', [userId]);
    })
    .then(eduscribes => {
      res.json(eduscribes);
    })
    .catch(error => {
      console.error('Error fetching EduScribe data:', error);
      res.status(500).json({ message: 'Internal server error' });
    });
});

// Delete EduScribe
app.delete('/api/deleteEduScribe/:id', (req, res) => {
  const id = req.params.id;

  const query = 'DELETE FROM eduscribes WHERE id = ?';
  connection.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error deleting eduscribe:', err);
      res.status(500).json({ message: 'Error deleting eduscribe' });
    } else {
      res.status(200).json({ message: 'EduScribe deleted successfully' });
    }
  });
});


// Backend API endpoint (Node.js + Express)
app.post('/get-user-results', (req, res) => {
  const token = req.body.token;

  getUserIdFromToken(token)
    .then(userId => {
      // Query user_quizzes table
      return query('SELECT * FROM user_quizzes WHERE user_id = ?', [userId]);
    })
    .then(userQuizzes => {
      const quizIds = userQuizzes.map(q => q.quiz_id);
      if (quizIds.length === 0) {
        return []; // No quizzes found, return empty array
      }

      // Query quizzes table
      return query('SELECT * FROM quizzes WHERE id IN (?)', [quizIds])
        .then(quizzes => {
          // Merge results from both queries
          const results = userQuizzes.map(quiz => {
            const quizInfo = quizzes.find(q => q.id === quiz.quiz_id);
            return {
              ...quiz,
              quiz_title: quizInfo ? quizInfo.title : 'Unknown Quiz'
            };
          });
          res.json({ results });
        });
    })
    .catch(error => {
      console.error('Error fetching results:', error);
      res.status(500).json({ message: 'Error fetching results' });
    });
});

app.post('/api/deleteQuiz', async (req, res) => {
  const { quizId } = req.body;

  try {
    // Delete quiz references in user_quizzes
    await query('DELETE FROM user_quizzes WHERE quiz_id = ?', [quizId]);

    // Delete quiz answers
    await query('DELETE FROM answers WHERE question_id IN (SELECT id FROM questions WHERE quiz_id = ?)', [quizId]);

    // Delete questions
    await query('DELETE FROM questions WHERE quiz_id = ?', [quizId]);

    // Delete quiz
    await query('DELETE FROM quizzes WHERE id = ?', [quizId]);

    res.status(200).send({ message: 'Quiz deleted successfully' });
  } catch (error) {
    console.error('Error deleting quiz:', error);
    res.status(500).send({ message: 'Failed to delete quiz' });
  }
});

// Route to increment download count only
app.post('/notes/increment-download-count/:id', (req, res) => {
  const noteId = req.params.id;

  // Increment the download count in the database
  connection.query(
      'UPDATE flashcards SET download_count = download_count + 1 WHERE id = ?',
      [noteId],
      (err, result) => {
          if (err) {
              console.error('Error updating download count:', err);
              return res.status(500).json({ error: 'Error updating download count' });
          }

          res.status(200).json({ message: 'Download count updated successfully' });
      }
  );
});


// Image upload route
app.post('/api/upload/images/flashcard', upload.single('image'), (req, res) => {
  if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded.' });
  }

  // Construct the URL for the uploaded image
  const imageUrl = `${req.protocol}://${req.get('host')}/${req.file.filename}`;
  res.status(200).json({ imageUrl });
});

// Check user details
app.post('/api/check-user-details', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: 'Token not provided' });
  }

  try {
    const userId = await getUserIdFromToken(token); // Assuming this function is already defined

    const results = await query('SELECT * FROM users WHERE id = ?', [userId]);

    if (results.length > 0) {
      const user = results[0];
      const emailMissing = !user.email || user.email.trim() === '';
      const phoneMissing = !user.phone_number || user.phone_number.trim() === '';
      return res.status(200).json({ emailMissing, phoneMissing });
    } else {
      return res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error checking user details:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Update user details
app.post('/api/update-user-details', async (req, res) => {
  const { token, email, phone } = req.body;

  // Check for the presence of the token
  if (!token) {
    return res.status(400).json({ message: 'Missing token' });
  }

  // Get userId from token
  let userId;
  try {
    userId = await getUserIdFromToken(token); // Assuming this function is defined
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }

  const updates = [];
  const params = [];

  if (email) {
    updates.push('email = ?');
    params.push(email);
  }
  if (phone) {
    updates.push('phone_number = ?');
    params.push(phone);
  }

  if (updates.length === 0) {
    return res.status(400).json({ message: 'No fields to update' });
  }

  try {
    await query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, [...params, userId]);
    return res.status(200).json({ message: 'User details updated successfully' });
  } catch (error) {
    console.error('Error updating user details:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});


app.post('/api/feedback', (req, res) => {
  const { feedback, token } = req.body;

  // If no token, set userId to 'website'
  const userIdPromise = token ? getUserIdFromToken(token) : Promise.resolve('website');

  // Proceed to save feedback
  userIdPromise
    .then((userId) => {
      // Prepare SQL query to save feedback and user ID into MySQL
      const sql = 'INSERT INTO feedback (user_id, message) VALUES (?, ?)';
      return query(sql, [userId, feedback]); // Use the promisified query function
    })
    .then(() => {
      // Log feedback on successful save
      console.log('User feedback received:', feedback); 

      // If successful, send success response
      return res.status(200).json({ message: 'Feedback saved successfully' });
    })
    .catch((error) => {
      // Handle errors from getting user ID or saving feedback
      console.error('Error processing feedback:', error);
      if (error instanceof jwt.JsonWebTokenError) {
        // If the error is due to invalid token
        return res.status(401).json({ message: 'Invalid token' });
      }
      // If the error is related to database insertion
      return res.status(500).json({ message: 'Error saving feedback' });
    });
});


const MAX_RETRIES = 10;

// Helper function to introduce a delay (in milliseconds)
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

app.post('/api/chat/ai', async (req, res) => {
  const { message, chatHistory, token } = req.body;

  try {
    // Validate required inputs
    if (!message || typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    if (!token) {
      return res.status(400).json({ error: 'Token is required.' });
    }

    // Get user ID from token
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not authenticated.' });
    }

    const initialChatHistory = [
      { role: 'user', parts: [{ text: 'Hello' }] },
      { role: 'model', parts: [{ text: 'Great to meet you. What would you like to know?' }] },
    ];

    const chat = model.startChat({ history: chatHistory || initialChatHistory });

    console.log('User asked:', message, userId);

    let aiResponse = '';

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        // Attempt to send message to AI
        const result = await chat.sendMessage(message);
        aiResponse = result.response?.text?.() || 'No response from AI.';
        console.log(`AI responded on attempt ${attempt}`);
        break; // Exit loop if successful
      } catch (error) {
        console.error(`Attempt ${attempt} failed:`, error.message);

        if (attempt === MAX_RETRIES) {
          throw new Error('AI service failed after multiple attempts.');
        }

        // Exponential backoff delay (2^attempt * 100 ms)
        const delayMs = Math.pow(2, attempt) * 100;
        console.log(`Retrying in ${delayMs}ms...`);
        await delay(delayMs);
      }
    }

    if (!aiResponse || aiResponse === 'No response from AI.') {
      return res.status(500).json({ error: 'AI service did not return a response.' });
    }

    // Store user message and AI response in the database
    await query('INSERT INTO ai_history (user_id, user_message, ai_response) VALUES (?, ?, ?)', [
      userId,
      message,
      aiResponse,
    ]);

    res.json({ response: aiResponse });
  } catch (error) {
    console.error('Error in /api/chat/ai endpoint:', error);

    res.status(500).json({ error: 'An error occurred while processing your request. Please try again later.' });
  }
});



app.post('/api/chat/ai/demo', async (req, res) => {
  const { message, chatHistory } = req.body;

  try {
    // Validate required inputs
    if (!message) {
      return res.status(400).json({ error: 'Message is required.' });
    }

    const initialChatHistory = [
      {
        role: 'user',
        parts: [{ text: 'Hello' }],
      },
      {
        role: 'model',
        parts: [{ text: 'Great to meet you. What would you like to know?' }],
      },
    ];

    const chat = model.startChat({
      history: chatHistory || initialChatHistory,
    });

    // Log the user's question
    console.log('User asked from website demo:', message);

    // Send message to the AI model and get the response
    const result = await chat.sendMessage(message);
    const aiResponse = result.response.text();

    // Log the AI's response
    console.log('AI responded');

    // Send the response back to the client
    res.json({ response: aiResponse });
  } catch (error) {
    // Handle errors
    console.error('Error in /api/chat/ai/demo endpoint:', error);

    let errorMessage = 'An error occurred while processing your request. Please try again later.';
    if (error.response) {
      errorMessage = `Error: ${error.response.status} - ${
        error.response.data?.message || error.response.statusText
      }`;
    } else if (error.message) {
      errorMessage = `Error: ${error.message}`;
    }

    // Log the final error message for debugging
    console.error('Final error message sent to user:', errorMessage);

    // Send a user-friendly error message
    res.status(500).json({ error: errorMessage });
  }
});


// Endpoint to fetch chat history
app.post('/api/chat/history/ai', async (req, res) => {
  const { token } = req.body;

  try {
    // Get user ID from the token
    const userId = await getUserIdFromToken(token);

    // Fetch chat history from the database
    const historyQuery = 'SELECT user_message, ai_response, created_at FROM ai_history WHERE user_id = ? ORDER BY created_at DESC';
    const chatHistory = await query(historyQuery, [userId]);

    // Format chat history for response
    const formattedHistory = chatHistory.flatMap(entry => ([
      {
        role: 'user',
        parts: [{ text: entry.user_message }],
        created_at: entry.created_at,
      },
      {
        role: 'model',
        parts: [{ text: entry.ai_response }],
        created_at: entry.created_at,
      },
    ]));

    // Send the chat history back to the client
    res.json(formattedHistory);
  } catch (error) {
    console.error('Error fetching chat history:', error);
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});


app.post('/api/getUserData/home/box', async (req, res) => {
  const { token } = req.body;

  try {
      const userId = await getUserIdFromToken(token); // Get userId from token

      // Fetch today's tasks and events where tasks are not completed
      const todayTasks = await query(
          'SELECT * FROM tasks WHERE user_id = ? AND due_date = CURDATE() AND completed = 0', 
          [userId]
      );
      const todayEvents = await query(
          'SELECT * FROM events WHERE user_id = ? AND date = CURDATE()', 
          [userId]
      );

      // Fetch upcoming tasks and events where tasks are not completed
      const upcomingTasks = await query(
          'SELECT * FROM tasks WHERE user_id = ? AND due_date > CURDATE() AND completed = 0', 
          [userId]
      );
      const upcomingEvents = await query(
          'SELECT * FROM events WHERE user_id = ? AND date > CURDATE()', 
          [userId]
      );

      // Respond with the data
      res.json({
          todayTasks: todayTasks, // Today's tasks
          todayEvents: todayEvents, // Today's events
          upcomingTasks: upcomingTasks, // Upcoming tasks
          upcomingEvents: upcomingEvents, // Upcoming events
      });
  } catch (error) {
      console.error('Error fetching user data:', error);
      res.status(500).json({ error: 'Failed to fetch user data' });
  }
});


app.post('/api/tasks/today/data/home', async (req, res) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('No token provided.');

  try {
      const userId = await getUserIdFromToken(token);
      const { due_date, upcoming } = req.body;

      let sql;
      const params = [userId];

      // Query for today's tasks or upcoming tasks based on the request
      if (upcoming) {
          sql = 'SELECT * FROM tasks WHERE user_id = ? AND due_date > CURDATE() AND completed = 0 ORDER BY due_date ASC';
      } else {
          sql = 'SELECT * FROM tasks WHERE user_id = ? AND due_date = ? AND completed = 0';
          params.push(due_date);
      }

      const tasks = await query(sql, params);
      res.json(tasks);
  } catch (error) {
      console.error('Error fetching tasks:', error);
      res.status(500).send('Error fetching tasks');
  }
});


app.post('/api/events/today/data/home', async (req, res) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('No token provided.');

  try {
      const userId = await getUserIdFromToken(token);
      const { event_date, upcoming } = req.body;

      let sql;
      const params = [userId];

      // Query for today's events or upcoming events based on the request
      if (upcoming) {
          sql = 'SELECT * FROM events WHERE user_id = ? AND date > CURDATE() ORDER BY date ASC';
      } else {
          sql = 'SELECT * FROM events WHERE user_id = ? AND date = ?';
          params.push(event_date);
      }

      const events = await query(sql, params);
      res.json(events);
  } catch (error) {
      console.error('Error fetching events:', error);
      res.status(500).send('Error fetching events');
  }
});


app.post('/api/update-avatar', upload.single('avatar'), async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]; // Extract Bearer token from the header

    if (!token) {
      return res.status(401).send('No token provided');
    }

    const userId = await getUserIdFromToken(token); // Get userId from token

    if (!req.file) {
      return res.status(400).send('No file uploaded');
    }

    const avatarFileName = req.file.filename;

    const query = 'UPDATE users SET avatar = ? WHERE id = ?';
    connection.query(query, [avatarFileName, userId], (err) => {
      if (err) {
        return res.status(500).send('Error updating avatar');
      }
      res.status(200).send('Avatar updated successfully');
    });
  } catch (error) {
    res.status(500).send('Error processing request');
  }
});

// Add a new route to handle avatar removal
app.delete('/api/remove-avatar', async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]; // Extract Bearer token from the header
    const userId = await getUserIdFromToken(token); // Get userId from token

    const defaultAvatar = 'defPic.png'; // or whatever your default is
    const query = 'UPDATE users SET avatar = ? WHERE id = ?';
    connection.query(query, [defaultAvatar, userId], (err) => {
      if (err) {
        return res.status(500).send('Error removing avatar');
      }
      res.status(200).send('Avatar removed successfully');
    });
  } catch (error) {
    res.status(500).send('Error processing request');
  }
});

// POST route to handle invitations
app.post('/invite/friend', async (req, res) => {
  try {
      const { token } = req.body;
      if (!token) return res.status(400).json({ error: 'No token provided' });

      // Call your helper function to get the userId
      const userId = await getUserIdFromToken(token);
      if (!userId) return res.status(401).json({ error: 'Invalid token' });

      // Insert the invitation event into the database
      connection.query('INSERT INTO invites (user_id) VALUES (?)', [userId], (err, result) => {
          if (err) {
              console.error('Error inserting invite:', err);
              return res.status(500).json({ error: 'Failed to log the invite' });
          }

          // Log to the console that the user invited someone
          console.log(`User ID ${userId} invited a friend!`);

          return res.status(200).json({ message: 'Invite logged successfully' });
      });
  } catch (error) {
      console.error('Error processing invite:', error);
      return res.status(500).json({ error: 'An error occurred' });
  }
});

// Start Pomodoro
app.post('/api/start/pomodoro', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract token from the authorization header

  if (!token) {
    return res.status(401).json({ message: 'Token is required' });
  }

  try {
    const userId = await getUserIdFromToken(token);
    console.log(`Pomodoro started for user: ${userId}`);

    const lastSessionQuery = 'SELECT updated_at FROM user_points WHERE user_id = ?';
    const [lastSessionResults] = await connection.promise().query(lastSessionQuery, [userId]);

    let canAwardPoints = true;
    if (lastSessionResults.length > 0) {
      const lastUpdated = new Date(lastSessionResults[0].updated_at);
      const now = new Date();
      const differenceInMinutes = Math.floor((now - lastUpdated) / 1000 / 60);

      if (differenceInMinutes < 25) {
        canAwardPoints = false;
      }
    }

    if (canAwardPoints) {
      const pointsQuery = 'SELECT * FROM user_points WHERE user_id = ?';
      const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

      if (pointsResults.length > 0) {
        await connection.promise().query('UPDATE user_points SET points = points + 5 WHERE user_id = ?', [userId]);
      } else {
        await connection.promise().query('INSERT INTO user_points (user_id, points) VALUES (?, ?)', [userId, 5]);
      }
    }

    // Insert a new Pomodoro session record
    const insertSessionQuery = 'INSERT INTO pomodoro_sessions (user_id, start_time, duration) VALUES (?, ?, ?)';
    const duration = 25; // Assuming a standard Pomodoro duration
    await connection.promise().query(insertSessionQuery, [userId, new Date(), duration]);

    res.status(200).json({ message: 'Pomodoro started' });
  } catch (error) {
    console.error('Error retrieving userId from token:', error);
    res.status(403).json({ message: 'Invalid token' });
  }
});


// Stop Pomodoro
app.post('/api/stop/pomodoro', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract token from the authorization header

  if (!token) {
    return res.status(401).json({ message: 'Token is required' });
  }

  try {
    const userId = await getUserIdFromToken(token);
    // Log stop for userId
    console.log(`Pomodoro stopped for user: ${userId}`);

    // Simply stop the Pomodoro without awarding points
    res.status(200).json({ message: 'Pomodoro stopped' });
  } catch (error) {
    console.error('Error retrieving userId from token:', error);
    res.status(403).json({ message: 'Invalid token' });
  }
});




// API endpoint to fetch leaderboard data
app.get('/api/leaderboard', (req, res) => {
  const sql = `
      SELECT u.id, u.unique_id, u.user_name, p.points, u.avatar
      FROM users u
      JOIN user_points p ON u.id = p.user_id
      ORDER BY p.points DESC
  `;
  
  connection.query(sql, (err, results) => {
      if (err) {
          console.error('Error fetching leaderboard data:', err);
          return res.status(500).json({ error: 'Failed to fetch leaderboard data' });
      }

      // Now check for premium users by fetching subscription data
      const subscriptionSql = `
          SELECT user_id FROM subscriptions`;
      connection.query(subscriptionSql, (err, subscriptionResults) => {
          if (err) {
              console.error('Error fetching subscription data:', err);
              return res.status(500).json({ error: 'Failed to fetch subscription data' });
          }

          // Create a set of premium user IDs
          const premiumUserIds = new Set(subscriptionResults.map(sub => sub.user_id));

          // Add an isPremium flag to each leaderboard user
          const leaderboardWithPremium = results.map(user => ({
              ...user,
              isPremium: premiumUserIds.has(user.id) // Check if the user is premium
          }));

          res.json(leaderboardWithPremium); // Return the leaderboard data along with the premium status
      });
  });
});


app.post('/api/flashcards/generate', async (req, res) => {
  const { set_id, subject, topic } = req.body; // Get subject, topic, and set_id from the request body

  try {
    // AI prompt to generate 15 question and answer flashcards
    const prompt = `Generate 15 flashcards in JSON format with questions and answers for the subject: ${subject} and topic: ${topic}. Each flashcard should be an object with 'question' and 'answer' fields, ensuring no additional text is included. Please do not use any Markdown formatting or backticks.`;

    const chat = model.startChat({
      history: [
        {
          role: 'user',
          parts: [{ text: 'Hello' }],
        },
        {
          role: 'model',
          parts: [{ text: 'I can help generate flashcards for your study!' }],
        },
      ],
    });

    console.log('Generating flashcards with prompt:', prompt);
    const result = await chat.sendMessage(prompt);

    // Sanitize the response to remove any unwanted characters
    const sanitizedResponse = result.response.text().replace(/```json|```|`/g, '').trim();

    // Expecting a JSON format response
    let flashcards;
    try {
      flashcards = JSON.parse(sanitizedResponse);
    } catch (parseError) {
      console.error('Failed to parse JSON:', parseError);
      return res.status(500).json({ error: 'Invalid JSON response from the AI model' });
    }

    // Prepare flashcards data to insert
    const flashcardsData = [];

    // Ensure that we have valid question-answer pairs
    for (const card of flashcards) {
      const question = card.question?.trim();
      const answer = card.answer?.trim();

      // Validate question and answer
      if (question && answer) {
        flashcardsData.push({ set_id, subject, topic, question, answer });
      } else {
        console.warn(`Skipping pair due to missing question or answer: ${question || 'No question'} - ${answer || 'No answer'}`);
      }
    }

    // Insert flashcards into the database if there are valid pairs
    if (flashcardsData.length > 0) {
      const flashcardsValues = flashcardsData.map(({ set_id, question, answer }) => [set_id, question, answer]);

      connection.query(
        'INSERT INTO flashcard (set_id, question, answer) VALUES ?',
        [flashcardsValues],
        (err) => {
          if (err) {
            console.error('Error inserting into database:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          // Return the generated flashcards
          res.json({ flashcards: flashcardsData });
        }
      );
    } else {
      res.status(400).json({ error: 'No valid flashcards generated' });
    }
  } catch (error) {
    console.error('Error generating flashcards:', error);
    let errorMessage = 'Failed to generate flashcards';
    if (error.response) {
      errorMessage = `Error: ${error.response.status} - ${error.response.data?.message || error.response.statusText}`;
    } else if (error.message) {
      errorMessage = `Error: ${error.message}`;
    }
    res.status(500).json({ error: errorMessage });
  }
});


app.get('/api/flashcards/view/individual/:id', (req, res) => {
  const { id } = req.params;

  const query = 'SELECT * FROM flashcard WHERE id = ?';
  connection.query(query, [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Check if any result was found
    if (results.length === 0) {
      return res.status(404).json({ error: 'Flashcard not found' });
    }

    // Send the flashcard details
    res.json(results[0]);
  });
});


// API to fetch all flashcard sets and statistics for a user
app.post('/api/flashcard-sets', async (req, res) => {
  const { token } = req.body; // Extract token from the body

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // Ensure that getUserIdFromToken is an async function and return the user ID correctly
    const userId = await getUserIdFromToken(token); // Await the promise here

    // Query to get all flashcard sets for the user
    const querySetsText = 'SELECT * FROM flashcard_sets WHERE user_id = ?';
    const sets = await query(querySetsText, [userId]); // Fetch all sets

    // Query to get the counts for flashcards based on status (I Know, I Don't Know)
    const queryFlashcardsStatsText = `
      SELECT 
        COUNT(*) AS totalFlashcards, 
        SUM(CASE WHEN fc.status = 'I Know' THEN 1 ELSE 0 END) AS flashcardsYouKnow,
        SUM(CASE WHEN fc.status = 'I Don''t Know' THEN 1 ELSE 0 END) AS flashcardsYouDontKnow
      FROM flashcard AS fc
      JOIN flashcard_sets AS fs ON fc.set_id = fs.id
      WHERE fs.user_id = ?`;

    const flashcardStats = await query(queryFlashcardsStatsText, [userId]); // Get stats for flashcards

    // Query to count the total number of flashcard sets
    const totalSetsCountText = 'SELECT COUNT(*) AS totalSets FROM flashcard_sets WHERE user_id = ?';
    const totalSets = await query(totalSetsCountText, [userId]); // Get total number of flashcard sets

    // Return the data including sets and stats
    res.json({
      sets: sets, // Return all sets for the user
      totalFlashcards: flashcardStats[0].totalFlashcards, // Total flashcards count
      flashcardsYouKnow: flashcardStats[0].flashcardsYouKnow, // "I Know" count
      flashcardsYouDontKnow: flashcardStats[0].flashcardsYouDontKnow, // "I Don't Know" count
      totalSets: totalSets[0].totalSets // Total sets count
    });
  } catch (error) {
    console.error('Error:', error.message); // Log any errors
    res.status(500).json({ error: 'An error occurred while fetching flashcard sets.' });
  }
});


// API to create a new flashcard set
app.post('/api/flashcard-sets/create', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from headers
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const userId = await getUserIdFromToken(token); // Get userId from token
    const { name, subject, topic } = req.body;
    
    const query = 'INSERT INTO flashcard_sets (name, subject, topic, user_id) VALUES (?, ?, ?, ?)';
    connection.query(query, [name, subject, topic, userId], (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: results.insertId });
    });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// API to fetch flashcards for a specific set along with set details
app.get('/api/flashcards/set/:id', (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT 
      f.*, 
      s.name AS set_name, 
      s.topic AS set_topic, 
      s.subject AS set_subject 
    FROM 
      flashcard f
    JOIN 
      flashcard_sets s ON f.set_id = s.id
    WHERE 
      f.set_id = ?`;

  connection.query(query, [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Extract flashcards
    const flashcards = results.map(result => ({
      id: result.id,
      question: result.question,
      answer: result.answer,
      set_id: result.set_id,
      set_name: result.set_name,
      set_topic: result.set_topic,
      status: result.status,
      set_subject: result.set_subject,
    }));

    // If no flashcards were found, return empty array and set details
    if (flashcards.length === 0) {
      return res.json({
        flashcards: [],
        setDetails: {
          name: '',
          topic: '',
          subject: '',
        },
      });
    }

    // Return flashcards and set details
    res.json({
      flashcards,
      setDetails: {
        name: flashcards[0].set_name,
        topic: flashcards[0].set_topic,
        subject: flashcards[0].set_subject,
      },
    });
  });
});

// API endpoint to get flashcard set data
app.get('/api/flashcard-set/data/:setId', (req, res) => {
  const { setId } = req.params;

  // Query to get the flashcard set data from the database
  const query = 'SELECT * FROM flashcard_sets WHERE id = ?'; // Adjust table name based on your schema

  connection.query(query, [setId], (error, results) => {
    if (error) {
      console.error('Error fetching flashcard set data:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (results.length > 0) {
      // If a set is found, return the entire row
      return res.json(results[0]);
    } else {
      return res.status(404).json({ error: 'Flashcard set not found' });
    }
  });
});

app.put('/api/flashcards/update-status/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // Get status from request body

  // Validate the input
  if (!status) {
    return res.status(400).json({ message: 'Status is required.' });
  }

  try {
    // Use the promisified query function
    const result = await query('UPDATE flashcard SET status = ? WHERE id = ?', [status, id]);
    
    if (result.affectedRows > 0) {
      res.status(200).json({ message: 'Flashcard status updated successfully.' });
    } else {
      res.status(404).json({ message: 'Flashcard not found.' });
    }
  } catch (error) {
    console.error('Error updating flashcard status:', error);
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});


// API endpoint to get flashcard stats
app.post('/api/flashcards/stats', (req, res) => {
  const setId = req.body.set_id; // Get set_id from request body

  if (!setId) {
      return res.status(400).json({ message: 'set_id is required' });
  }

  connection.query('SELECT * FROM flashcard WHERE set_id = ?', [setId], (err, results) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }

      const totalCards = results.length;
      let knownCount = 0;
      let unknownCount = 0;

      results.forEach(card => {
          if (card.status === 'I Know') {
              knownCount++;
          } else if (card.status === "I Don't Know") {
              unknownCount++;
          }
      });

      const knownPercentage = totalCards ? (knownCount / totalCards) * 100 : 0;

      res.json({
          totalCards,
          knownCount,
          unknownCount,
          knownPercentage: knownPercentage.toFixed(2),
      });
  });
});


// API endpoint to delete a flashcard
app.delete('/api/flashcards/individual/:id', (req, res) => {
  const flashcardId = req.params.id;

  connection.query('DELETE FROM flashcard WHERE id = ?', [flashcardId], (err, results) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }

      res.json({ message: 'Flashcard deleted successfully' });
  });
});


// API endpoint to create a flashcard
app.post('/api/flashcards/create/manual', (req, res) => {
  const { question, set_id, answer } = req.body;

  // Validate the input
  if (!question || !set_id || !answer) {
    return res.status(400).json({ message: 'Question, set_id, and answer are required' });
  }

  // SQL query to insert a new flashcard
  const sql = 'INSERT INTO flashcard (question, set_id, answer) VALUES (?, ?, ?)';
  const values = [question, set_id, answer];

  connection.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error inserting flashcard:', err);
      return res.status(500).json({ error: 'Failed to create flashcard' });
    }

    res.status(201).json({ message: 'Flashcard created successfully', flashcardId: result.insertId });
  });
});

// API endpoint to delete a flashcard set and its associated flashcards
app.delete('/api/flashcards/set/delete/:id', async (req, res) => {
  const setId = req.params.id;

  try {
    // Start a transaction
    await query('START TRANSACTION');

    // SQL query to delete all flashcards associated with the set_id
    await query('DELETE FROM flashcard WHERE set_id = ?', [setId]);

    // SQL query to delete the flashcard set
    await query('DELETE FROM flashcard_sets WHERE id = ?', [setId]);

    // Commit the transaction
    await query('COMMIT');

    // Successful deletion
    res.status(200).json({ message: 'Flashcard set and associated flashcards deleted successfully' });
  } catch (error) {
    // Rollback in case of an error
    await query('ROLLBACK');
    console.error('Error deleting flashcard set or associated flashcards:', error);
    res.status(500).json({ error: 'Failed to delete flashcard set or associated flashcards' });
  }
});


// API endpoint to create a subject
app.post('/api/create-subject', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from header
  const { subjectName } = req.body;

  if (!token) {
      return res.status(401).json({ message: 'Token is required' });
  }

  try {
      const userId = await getUserIdFromToken(token); // Get userId from token

      // Insert subject into the database
      const result = await query('INSERT INTO subjects (user_id, name) VALUES (?, ?)', [userId, subjectName]);

      // Respond with the created subject
      return res.status(201).json({ subject: { id: result.insertId, userId, name: subjectName } });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Internal server error' });
  }
});


app.get('/api/get/user/subjects', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
  }

  connection.query('SELECT user_id FROM session WHERE jwt = ?', [token], (err, results) => {
      if (err) {
          console.error('Error fetching user_id:', err);
          return res.status(500).json({ message: 'Failed to authenticate user.' });
      }

      if (results.length === 0) {
          return res.status(401).json({ message: 'Invalid or expired token.' });
      }

      const userId = results[0].user_id;

      connection.query('SELECT * FROM subjects WHERE user_id = ?', [userId], (err, notes) => {
          if (err) {
              console.error('Error fetching notes:', err);
              return res.status(500).json({ message: 'Failed to retrieve notes.' });
          }
          res.json(notes);
      });
  });
});
app.get('/api/flashcards/:subjectId', (req, res) => {
  const { subjectId } = req.params; // Get subjectId from URL parameters
  const token = req.headers['authorization']?.split(' ')[1]; // Get token from headers

  if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
  }

  // Get user ID from the token
  getUserIdFromToken(token)
      .then((userId) => {
          // Query to fetch flashcards and subject name based on subject ID
          const query = `
              SELECT f.*, s.name AS subject_name 
              FROM flashcards f 
              JOIN subjects s ON f.subject_id = s.id 
              WHERE f.subject_id = ? AND f.user_id = ?
          `;
          connection.query(query, [subjectId, userId], (error, results) => {
              if (error) {
                  console.error('Error fetching flashcards:', error);
                  return res.status(500).json({ message: 'Failed to fetch flashcards.' });
              }

              res.status(200).json(results); // Send the fetched flashcards and subject name as a response
          });
      })
      .catch((error) => {
          console.error('Error fetching user ID:', error);
          res.status(500).json({ message: 'Failed to authenticate user.' });
      });
});

app.post('/api/generate/ai/today/plan/tasks', async (req, res) => {
  const { token, AI_task_generation_instructions } = req.body;

  try {
    // Validate token and get user ID
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not found' });
    }

    // Validate AI instructions
    if (!AI_task_generation_instructions) {
      return res.status(400).json({ error: 'Missing AI task generation instructions' });
    }

    // Get today's date in YYYY-MM-DD format
    const todayDate = new Date().toISOString().split('T')[0];

    // Generate prompt with today's date
    const prompt = `
    You are an AI designed to generate structured task plans for Edusify users for today, ${todayDate}. Your output should only contain valid JSON without any additional text. Please generate a highly detailed, structured task plan for the user to complete within today, ${todayDate}. The JSON structure should follow this exact format:
  
    [
      {
        "title": "Task title summarizing the specific action",
        "description": "Brief description with clear, actionable steps, necessary resources, helpful suggestions, and motivational reminders.",
        "due_date": "${todayDate}",
        "priority": "Low | Normal | High",
        "estimated_time": "Number of minutes for task completion"
      },
      ...
    ]
  
    The tasks should be relevant to a student using Edusify. Focus on tasks related to studying, reviewing, organizing, and using Edusify features like:
    - Attending quizzes
    - Reviewing and completing flashcards
    - Creating and reviewing study notes
    - Generating AI-powered quizzes or notes
    - Organizing tasks with to-do lists and study plans
    - Using the Pomodoro timer for study sessions
    - Analyzing progress with personalized stats
  
    The descriptions should be brief but actionable, encouraging the user to make the most of Edusify's tools, while staying motivated and organized throughout their study session.
  
    Follow these specific instructions: ${AI_task_generation_instructions}
    Return **only the JSON** as the response without any explanations, comments, or code blocks. If the input is invalid or insufficient to generate a task plan, return an empty JSON array: [].
  `;
  

    console.log('Generating tasks with prompt:', prompt);

    // Generate tasks with retry logic
    const generateTasksWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          // Call the AI model with the prompt
          const chat = model.startChat({
            history: [
              { role: 'user', parts: [{ text: 'Hello' }] },
              { role: 'model', parts: [{ text: 'I can help generate tasks for your project!' }] },
            ],
          });

          const result = await chat.sendMessage(prompt);

          // Extract only the JSON part using a regular expression
          const responseText = result.response.text();
          const jsonResponse = responseText.match(/```json([\s\S]*?)```/);
          if (!jsonResponse || jsonResponse.length < 2) {
            throw new Error('Could not extract JSON from AI response');
          }

          // Parse the JSON
          let tasks;
          try {
            tasks = JSON.parse(jsonResponse[1].trim());
          } catch (parseError) {
            console.error('Failed to parse JSON:', parseError);
            throw new Error('Invalid JSON response from the AI model.');
          }

          // Ensure tasks is an array
          if (!Array.isArray(tasks)) {
            console.error('AI response does not contain an array of tasks.');
            throw new Error('Invalid task structure returned from AI model.');
          }

          return tasks;  // Return the successfully generated tasks
        } catch (error) {
          attempts++;
          console.log(`Attempt ${attempts} failed, retrying...`);

          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate tasks after multiple attempts');
          }

          // Delay before retrying
          await delay(2000); // Delay for 2 seconds before the next attempt
        }
      }
    };

    const tasks = await generateTasksWithRetry();

    // Prepare tasks for database insertion
    const tasksData = tasks.map(task => ({
      userId,
      title: task.title?.trim() || 'Untitled Task',
      description: task.description?.trim() || 'No description provided',
      due_date: task.due_date?.trim() || todayDate,
      priority: task.priority?.trim() || 'Normal',
    }));

    if (tasksData.length > 0) {
      const tasksValues = tasksData.map(({ userId, title, description, due_date, priority }) => [
        userId,
        title,
        description,
        due_date,
        priority,
      ]);

      // Insert tasks into the database
      await query('INSERT INTO tasks (user_id, title, description, due_date, priority) VALUES ?', [tasksValues]);

      res.json({ tasks: tasksData });
    } else {
      res.status(400).json({ error: 'No valid tasks generated' });
    }
  } catch (error) {
    console.error('Error generating tasks:', error);
    res.status(500).json({ error: error.message || 'Failed to generate tasks' });
  }
});



app.post('/api/tasks/generate', async (req, res) => {
  const { mainTask, days, token, taskStyle } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not found' });
    }

    // Get today's date in YYYY-MM-DD format
    const todayDate = new Date().toISOString().split('T')[0];

    const prompt = taskStyle === 'detailed'
      ? `You are an AI designed to generate structured task plans. Your output should only contain valid JSON without any additional text. Please generate a highly detailed and structured task plan in JSON format, breaking down the main task: "${mainTask}" into smaller tasks to be completed within ${days} days. The JSON structure should follow this exact format:

      [
        {
          "title": "Task title summarizing the specific action",
          "description": "Detailed description with clear, actionable steps, necessary resources, helpful suggestions, and motivational reminders.",
          "due_date": "YYYY-MM-DD",
          "priority": "Low | Normal | High",
          "estimated_time": "Number of hours for task completion"
        },
        ...
      ]
      
      The task plan should meet the following requirements:
      1. Tasks should be logically sequenced, with each step building on the previous ones, creating a clear path from start to finish.
      2. Distribute the tasks evenly over ${days} days, starting from today (${todayDate}).
      3. Include periodic checkpoints to review progress and rest days to prevent burnout.
      4. Descriptions should be motivational, actionable, and specific.
      5. Ensure the workload is balanced and realistic for each day.
      
      Return **only the JSON** as the response without any explanations, comments, or code blocks. If the input is invalid or insufficient to generate a task plan, return an empty JSON array: [].`
      : `You are an advanced AI assistant specializing in creating structured task plans. Your task is to generate a highly detailed and well-organized task plan in valid JSON format, breaking down the main task: "${mainTask}" into smaller, actionable steps that can be completed within ${days} days, starting from today (${todayDate})..`;

    console.log('Generating tasks with prompt:', prompt);

    // Function to attempt generating tasks and retry on failure
    const generateTasksWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          // Call the AI model with the prompt
          const chat = model.startChat({
            history: [
              { role: 'user', parts: [{ text: 'Hello' }] },
              { role: 'model', parts: [{ text: 'I can help generate tasks for your project!' }] },
            ],
          });

          const result = await chat.sendMessage(prompt);

          // Extract only the JSON part using a regular expression
          const responseText = result.response.text();
          const jsonResponse = responseText.match(/```json([\s\S]*?)```/);
          if (!jsonResponse || jsonResponse.length < 2) {
            throw new Error('Could not extract JSON from AI response');
          }

          // Parse the JSON
          let tasks;
          try {
            tasks = JSON.parse(jsonResponse[1].trim());
          } catch (parseError) {
            console.error('Failed to parse JSON:', parseError);
            throw new Error('Invalid JSON response from the AI model.');
          }

          // Ensure tasks is an array
          if (!Array.isArray(tasks)) {
            console.error('AI response does not contain an array of tasks.');
            throw new Error('Invalid task structure returned from AI model.');
          }

          return tasks;  // Return the successfully generated tasks
        } catch (error) {
          attempts++;
          console.log(`Attempt ${attempts} failed, retrying...`);

          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate tasks after multiple attempts');
          }

          // Delay before retrying
          await delay(2000); // Delay for 2 seconds before the next attempt
        }
      }
    };

    // Try to generate tasks with retries
    const tasks = await generateTasksWithRetry();

    const tasksData = tasks.map(task => ({
      userId,
      title: task.title?.trim() || 'Untitled Task',
      description: task.description?.trim() || 'No description provided',
      due_date: task.due_date?.trim() || new Date().toISOString().split('T')[0],
      priority: task.priority?.trim() || 'Normal',
    }));

    if (tasksData.length > 0) {
      const tasksValues = tasksData.map(({ userId, title, description, due_date, priority }) => [userId, title, description, due_date, priority]);

      // Insert tasks into the database
      await query('INSERT INTO tasks (user_id, title, description, due_date, priority) VALUES ?', [tasksValues]);

      res.json({ tasks: tasksData });
    } else {
      res.status(400).json({ error: 'No valid tasks generated' });
    }
  } catch (error) {
    console.error('Error generating tasks:', error);

    // Provide a default error message
    let errorMessage = 'Failed to generate tasks';
    if (error.response) {
      errorMessage = `Error: ${error.response.status} - ${error.response.data?.message || error.response.statusText}`;
    } else if (error.message) {
      errorMessage = `Error: ${error.message}`;
    }

    res.status(500).json({ error: errorMessage });
  }
});


app.set('trust proxy', true); // Enable this if you're behind a reverse proxy
// Define the route to accept cookie data
app.post('/api/cookies', (req, res) => {
  const { cookieConsent, timestamp, browser, device, referrerUrl } = req.body;

  // Get the user's real IP address
  const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  if (cookieConsent === undefined || !timestamp) {
    return res.status(400).send('Invalid cookie data');
  }

  // Log the collected cookie data
  console.log('Collected Cookie Data:', {
    cookieConsent,
    timestamp,
    browser,
    device,
    ipAddress,
    referrerUrl
  });

  // Insert cookie data into the database
  const query = `
    INSERT INTO user_cookies (cookie_consent, timestamp, browser, device, ip_address, referrer_url) 
    VALUES (?, ?, ?, ?, ?, ?)`;

  connection.query(query, [cookieConsent, timestamp, browser, device, ipAddress, referrerUrl], (err, result) => {
    if (err) {
      console.error('Error inserting data into MySQL:', err);
      return res.status(500).send('Server error');
    }
    res.status(200).send('Cookie data saved successfully');
  });
});



// 5. Delete a subject
app.delete('/subjects/delete/:id', (req, res) => {
  const id = req.params.id
  const sql = 'DELETE FROM subjects WHERE id = ?';
  connection.query(sql, [id], (err, result) => {
    if (err) {
      return res.status(500).send('Error deleting subject');
    }
    if (result.affectedRows === 0) {
      return res.status(404).send('Subject not found');
    }
    res.send('Subject deleted successfully');
  });
});

// Route to fetch recommended educational video IDs
app.get('/api/youtube/recommendations', async (req, res) => {
  try {
    const keywords = ['education', 'discipline', 'motivation', 'study tips', 'career advice'];
    const keywordQuery = keywords.join('|'); // Create a regex-like query for multiple keywords

    const searchResponse = await axios.get('https://www.googleapis.com/youtube/v3/search', {
      params: {
        part: 'id',
        q: keywordQuery,
        key: 'AIzaSyBwuCm6uF1j1BkK_I5xIUuRpZDqyJrhXxw',
        type: 'video',
        maxResults: 10, // Increase results to filter later
        relevanceLanguage: 'en',
        safeSearch: 'strict'
      }
    });

    // Filter out shorts and get video IDs
    const videoIds = searchResponse.data.items
      .filter(item => item.id.videoId && !item.id.videoId.includes("shorts"))
      .map(item => item.id.videoId);

    // Step 2: Fetch Video Details for Each ID
    const videoDetailsResponse = await axios.get('https://www.googleapis.com/youtube/v3/videos', {
      params: {
        part: 'snippet,statistics,contentDetails', // Include contentDetails to access duration
        id: videoIds.join(','),
        key: 'AIzaSyBwuCm6uF1j1BkK_I5xIUuRpZDqyJrhXxw'
      }
    });

    // Step 3: Filter for high view counts, likes, duration, and exclude specified channels
    const excludedChannels = [
      'ExpHub', // Exclude this channel
      'ExpHub - Prashant Kirad'
    ];

    const videos = videoDetailsResponse.data.items
      .filter(video => 
        video.contentDetails && // Ensure contentDetails exists
        Number(video.statistics.viewCount) > 100000 && // Adjusted
        Number(video.statistics.likeCount) > 1000 && // Adjusted
        video.contentDetails.duration &&
        convertDurationToSeconds(video.contentDetails.duration) > 60 && // Adjusted
        !excludedChannels.some(channel => channel.toLowerCase() === video.snippet.channelTitle.toLowerCase()) // Exclude specified channels (case insensitive)
      )
      .map(item => ({
        videoId: item.id,
        title: item.snippet.title,
        description: item.snippet.description,
        thumbnail: item.snippet.thumbnails.default.url,
        viewCount: item.statistics.viewCount,
        likeCount: item.statistics.likeCount, // Optionally include like count
        channelTitle: item.snippet.channelTitle // Include channel title for context
      }));

    res.json(videos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch recommended videos' });
  }
});

// Helper function to convert ISO 8601 duration to seconds
const convertDurationToSeconds = (duration) => {
  const match = duration.match(/PT(\d+H)?(\d+M)?(\d+S)?/);
  const hours = match[1] ? parseInt(match[1]) * 3600 : 0;
  const minutes = match[2] ? parseInt(match[2]) * 60 : 0;
  const seconds = match[3] ? parseInt(match[3]) : 0;
  return hours + minutes + seconds;
};



// Route to search YouTube videos
app.get('/api/youtube/search', async (req, res) => {
  const { query } = req.query;

  try {
    const response = await axios.get(
      `https://www.googleapis.com/youtube/v3/search`,
      {
        params: {
          part: 'snippet',
          q: query,
          key: 'AIzaSyBwuCm6uF1j1BkK_I5xIUuRpZDqyJrhXxw',
          type: 'video', // Ensures only videos are returned
          maxResults: 10
        }
      }
    );

    const videos = response.data.items
      .filter(item => item.id.videoId) // Ensure videoId exists
      .map(item => ({
        videoId: item.id.videoId,
        title: item.snippet.title,
        description: item.snippet.description,
        thumbnail: item.snippet.thumbnails.default.url
      }));

    res.json(videos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Route to create a new folder
app.post('/api/folders/add', async (req, res) => {
  const { token, folderName } = req.body;

  if (!folderName) {
    return res.status(400).json({ error: 'Folder name is required' });
  }

  try {
    const userId = await getUserIdFromToken(token);
    const sql = 'INSERT INTO folders (name, user_id) VALUES (?, ?)';
    await query(sql, [folderName, userId]);
    res.status(201).json({ message: 'Folder created successfully' });
  } catch (error) {
    console.error('Error creating folder:', error);
    res.status(500).json({ error: 'Failed to create folder' });
  }
});
// Route to upload a new document
app.post('/api/documents/add', upload.array('files', 5), async (req, res) => {
  const { token, title, description, password, folderId } = req.body;

  // Check if the token is provided
  if (!token) {
    return res.status(401).json({ error: 'Token is required' });
  }

  // Check if the title is provided
  if (!title) {
    return res.status(400).json({ error: 'Document title is required' });
  }

  // Check if files were uploaded
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'At least one file is required' });
  }

  try {
    // Get user ID from the token
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Insert the document into the database
    const sql = 'INSERT INTO documents (title, description, password, user_id, folder_id) VALUES (?, ?, ?, ?, ?)';
    const result = await query(sql, [title, description, password, userId, folderId || null]);

    const documentId = result.insertId;

    // Insert only the file name, not the full path
    const filePromises = req.files.map(file => {
      const fileName = file.filename; // Use the stored filename from Multer
      const fileSql = 'INSERT INTO document_files (document_id, file_name) VALUES (?, ?)';
      return query(fileSql, [documentId, fileName]);
    });

    await Promise.all(filePromises);

    // Log success message
    console.log(`Document uploaded successfully with ID: ${documentId}`);

    res.status(201).json({ message: 'Document uploaded successfully' });
  } catch (error) {
    console.error('Error uploading document:', error);
    res.status(500).json({ error: 'Failed to upload document' });
  }
});

// Route to retrieve all folders for a user
app.post('/api/folders/get', async (req, res) => {
  const token = req.body.token; // Expecting token in the body

  try {
    const userId = await getUserIdFromToken(token);
    const sql = 'SELECT * FROM folders WHERE user_id = ?';
    const folders = await query(sql, [userId]);
    res.status(200).json(folders);
  } catch (error) {
    console.error('Error fetching folders:', error);
    res.status(500).json({ error: 'Failed to fetch folders' });
  }
});

// Route to retrieve all documents
app.post('/api/documents/get', async (req, res) => {
  const token = req.body.token;

  try {
    const userId = await getUserIdFromToken(token);
    const sql = 'SELECT * FROM documents WHERE user_id = ?'; // Fetch all documents for the user
    const documents = await query(sql, [userId]);
    res.json(documents);
  } catch (error) {
    console.error('Error fetching documents:', error);
    res.status(500).send('Server Error');
  }
});

// Route to retrieve documents by folder ID
app.post('/api/documents/getByFolder', async (req, res) => {
  const { token, folderId } = req.body;

  try {
    const userId = await getUserIdFromToken(token); // Ensure you're validating the user's token
    const sql = 'SELECT * FROM documents WHERE user_id = ? AND folder_id = ?'; // Fetch documents for the specified folder
    const documents = await query(sql, [userId, folderId]); // Pass user ID and folder ID to the query
    res.json(documents);
  } catch (error) {
    console.error('Error fetching documents by folder:', error);
    res.status(500).send('Server Error');
  }
});

// Route to retrieve folder details by folder ID
app.post('/api/folders/get/details', async (req, res) => {
  const { token, folderId } = req.body;

  try {
    const userId = await getUserIdFromToken(token); // Ensure user is validated
    const sql = 'SELECT name FROM folders WHERE user_id = ? AND id = ?'; // Fetch folder name
    const folder = await query(sql, [userId, folderId]);
    res.json(folder[0]); // Return the first matching folder
  } catch (error) {
    console.error('Error fetching folder details:', error);
    res.status(500).send('Server Error');
  }
});



// Route to retrieve a document by ID
app.post('/api/documents/view', async (req, res) => {
  const { token, documentId, password } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    
    // Query to find the document
    const sqlDocument = 'SELECT * FROM documents WHERE id = ? AND user_id = ?';
    const [document] = await query(sqlDocument, [documentId, userId]);

    // Check if the document exists
    if (!document) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // Check if the document has a password
    if (document.password && document.password !== password) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    // Query to find associated files (images)
    const sqlFiles = 'SELECT * FROM document_files WHERE document_id = ?';
    const files = await query(sqlFiles, [documentId]);

    // Send document and associated files
    res.status(200).json({ document, files });
  } catch (error) {
    console.error('Error retrieving document:', error);
    res.status(500).json({ error: 'Failed to retrieve document' });
  }
});


// Endpoint to get notes for a specific user
app.post('/api/sticky-notes/get', async (req, res) => {
  const { token } = req.body;
  try {
      const userId = await getUserIdFromToken(token);
      connection.query('SELECT * FROM sticky_notes WHERE user_id = ? AND deleted = 0', [userId], (err, results) => {
          if (err) throw err;
          res.json(results);
      });
  } catch (error) {
      res.status(401).json({ message: 'Unauthorized' });
  }
});

// Endpoint to add a new note for a specific user
app.post('/api/sticky-notes/add', async (req, res) => {
  const { token, title, description, color, fontColor } = req.body;
  try {
      const userId = await getUserIdFromToken(token); // Retrieve user_id using the token
      const sql = 'INSERT INTO sticky_notes (title, description, color, fontColor, user_id) VALUES (?, ?, ?, ?, ?)';
      connection.query(sql, [title, description, color, fontColor, userId], (err, result) => {
          if (err) throw err;

          // Log the note details to the console
          console.log(`New note added by user ${userId}:`);

          res.status(201).json({ id: result.insertId, title, description, color, fontColor });
      });
  } catch (error) {
      res.status(401).json({ message: 'Unauthorized' });
  }
});


// Endpoint to mark a sticky note as deleted by ID
app.delete('/api/sticky-notes/delete/:noteId', async (req, res) => {
  const { noteId } = req.params;
  const { token } = req.body;

  try {
      const userId = await getUserIdFromToken(token);

      // Update the note's deleted status instead of deleting it
      connection.query('UPDATE sticky_notes SET deleted = 1 WHERE id = ? AND user_id = ?', [noteId, userId], (err, results) => {
          if (err) {
              console.error(err);
              return res.status(500).json({ message: 'Failed to delete note' });
          }
          if (results.affectedRows === 0) {
              return res.status(404).json({ message: 'Note not found' });
          }
          res.status(200).json({ message: 'Note marked as deleted successfully' });
      });
  } catch (error) {
      console.error('Error marking note as deleted:', error);
      res.status(401).json({ message: 'Unauthorized' });
  }
});

// Endpoint to update the pinned status of a sticky note by ID
app.put('/api/sticky-notes/pin/:noteId', async (req, res) => {
  const { noteId } = req.params; // Get noteId from URL parameters
  const { token, pinned } = req.body; // Get token and pinned status from request body

  try {
      const userId = await getUserIdFromToken(token); // Retrieve user_id using the token

      // Update the pinned status in the database
      const sql = 'UPDATE sticky_notes SET pinned = ? WHERE id = ? AND user_id = ?';
      connection.query(sql, [pinned ? 1 : 0, noteId, userId], (err, results) => {
          if (err) {
              console.error(err);
              return res.status(500).json({ message: 'Failed to update pinned status' });
          }
          if (results.affectedRows === 0) {
              return res.status(404).json({ message: 'Note not found' });
          }
          res.status(200).json({ message: 'Pinned status updated successfully' });
      });
  } catch (error) {
      console.error('Error updating pinned status:', error);
      res.status(401).json({ message: 'Unauthorized' });
  }
});

// Route to log daily login
app.post('/login-track', async (req, res) => {
  try {
    const token = req.headers.authorization;
    const userId = await getUserIdFromToken(token); // Get user ID from token

    // Use the promisified query function to insert the login record, using NOW() to get the current timestamp
    const result = await query(
      `INSERT IGNORE INTO user_logins (user_id, login_date, login_time) 
       VALUES (?, CURDATE(), CURTIME())`,
      [userId]
    );

    if (result.affectedRows === 0) {
      return res.status(200).json({ message: 'Already logged today' });
    }

    res.status(201).json({ message: 'Login recorded' });
  } catch (error) {
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Monthly stats route
app.post('/api/stats/monthly', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).json({ error: 'Token is required' });
  }

  try {
    const userId = await getUserIdFromToken(token);

    const currentTime = Math.floor(Date.now() / 1000); // Get current time in seconds

    // Fetch stats from the database for the current month
    const completedTasks = await connection.promise().query(
      'SELECT COUNT(*) AS total_completed FROM tasks WHERE completed = 1 AND user_id = ? AND MONTH(completed_at) = MONTH(CURDATE()) AND YEAR(completed_at) = YEAR(CURDATE())',
      [userId]
    );

    const pendingTasks = await connection.promise().query(
      'SELECT COUNT(*) AS total_pending FROM tasks WHERE completed = 0 AND user_id = ? AND MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())',
      [userId]
    );

    const pomodoroSessions = await connection.promise().query(
      'SELECT COUNT(*) AS total_sessions FROM pomodoro_sessions WHERE user_id = ? AND MONTH(start_time) = MONTH(CURDATE()) AND YEAR(start_time) = YEAR(CURDATE())',
      [userId]
    );

    const quizzes = await connection.promise().query(
      'SELECT AVG(score) AS average_score, COUNT(*) AS quizzes_attended FROM user_quizzes WHERE user_id = ? AND MONTH(completed_at) = MONTH(CURDATE()) AND YEAR(completed_at) = YEAR(CURDATE())',
      [userId]
    );

    const aiInteractions = await connection.promise().query(
      'SELECT COUNT(*) AS total_interactions FROM ai_history WHERE user_id = ? AND MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())',
      [userId]
    );

    // New query to fetch the number of daily logins for the current month
    const dailyLogins = await connection.promise().query(
      'SELECT COUNT(DISTINCT login_date) AS daily_logins FROM user_logins WHERE user_id = ? AND MONTH(login_date) = MONTH(CURDATE()) AND YEAR(login_date) = YEAR(CURDATE())',
      [userId]
    );

    const statsData = {
      totalCompletedTasks: completedTasks[0][0].total_completed,
      totalPendingTasks: pendingTasks[0][0].total_pending,
      pomodoroSessions: pomodoroSessions[0][0].total_sessions,
      averageQuizScore: quizzes[0][0].average_score || 0,
      quizzesAttended: quizzes[0][0].quizzes_attended,
      aiInteractions: aiInteractions[0][0].total_interactions,
      dailyLogins: dailyLogins[0][0].daily_logins,
    };
    
    res.json(statsData);
    
  } catch (error) {
    console.error("Error fetching stats:", error); // Debugging log
    res.status(401).json({ error: 'Unauthorized: ' + error.message });
  }
});

// Endpoint to fetch the user's streak
app.post('/api/streak', async (req, res) => {
  const { token } = req.body;

  try {
    // Get user ID from token
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Query to fetch completed tasks in ascending order by date
    const query = `
      SELECT DATE(completed_at) as completedDate
      FROM tasks
      WHERE user_id = ? AND completed_at IS NOT NULL
      ORDER BY completed_at ASC
    `;

    connection.query(query, [userId], (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ error: 'Failed to load streak data.' });
      }

      // Calculate streaks
      let streakCount = 0;
      let currentStreak = 0;
      let lastDate = null;

      results.forEach((row) => {
        const completedDate = new Date(row.completedDate);

        // If it's the first entry or the day after the last streak date, increment the streak
        if (!lastDate || completedDate.getTime() === lastDate.getTime() + 86400000) {
          currentStreak++;
        } else if (completedDate.getTime() !== lastDate.getTime()) {
          currentStreak = 1; // Reset streak if there's a gap
        }
        streakCount = Math.max(streakCount, currentStreak);
        lastDate = completedDate;
      });

      res.json({ streakCount });
    });
  } catch (error) {
    console.error('Error fetching streak data:', error);
    res.status(500).json({ error: 'Failed to load streak data.' });
  }
});




// Endpoint to save the drawing, text, and image notes
app.post('/api/save/canvas', (req, res) => {
  const { image, notes } = req.body;
  const query = 'INSERT INTO notes (image, notes) VALUES (?, ?)';
  
  connection.query(query, [image, JSON.stringify(notes)], (err, result) => {
    if (err) return res.status(500).send(err);
    res.status(200).send({ id: result.insertId });
  });
});

app.get('/api/notes/canvas/get', (req, res) => {
  console.log('Fetching notes...');
  connection.query('SELECT * FROM notes ORDER BY created_at DESC', (err, results) => {
      if (err) {
          console.error('Error fetching notes:', err);
          return res.status(500).json({ error: err.message });
      }

      res.json(results);
  });
});

app.post('/start-session/pomodoro', async (req, res) => {   
  const { token, session_type } = req.body;  // Get token and session_type from request body   
  
  if (!token) {     
      return res.status(403).json({ message: 'No token provided' });   
  }    
  
  try {     
      const user_id = await getUserIdFromToken(token);     
      const start_time = new Date();     
      const session_date = start_time.toISOString().split('T')[0]; // Format as YYYY-MM-DD  

      // Start Pomodoro session     
      const insertQuery = 'INSERT INTO pomodoro_date (user_id, start_time, session_date, session_type) VALUES (?, ?, ?, ?)';     
      const result = await query(insertQuery, [user_id, start_time, session_date, session_type]);      

      // Log when Pomodoro session starts for the user     
      console.log(`Pomodoro session started for userId: ${user_id}`);      

      // Check if user_points row exists for the user
      const checkPointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';  
      const pointsResult = await query(checkPointsQuery, [user_id]);  

      if (pointsResult.length === 0) { 
          // If no row exists, insert a new one with initial points
          const insertPointsQuery = 'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)';
          await query(insertPointsQuery, [user_id, 5, start_time]);  // Assuming initial points are 5
      } else { 
          const lastUpdated = new Date(pointsResult[0].updated_at);
          const timeDifference = (start_time - lastUpdated) / 1000 / 60; // Difference in minutes

          if (timeDifference >= 3) {
              // If last updated more than 3 minutes ago, update points
              const updatePointsQuery = 'UPDATE user_points SET points = points + 5, updated_at = ? WHERE user_id = ?';
              await query(updatePointsQuery, [start_time, user_id]);  
          } else {
              console.log(`Points not updated for userId: ${user_id} as the last update was less than 3 minutes ago.`);
          }
      }

      // Return the session ID and start time     
      res.json({ session_id: result.insertId, start_time });   
  } catch (error) {     
      res.status(401).json({ message: 'Invalid or expired token' });   
  } 
});



app.post('/end-session/pomodoro', async (req, res) => {
  const { session_id, token, session_type } = req.body;  // Get session_id, token, and session_type from request body
  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  try {
    const user_id = await getUserIdFromToken(token);
    const end_time = new Date();

    const updateQuery = 'UPDATE pomodoro_date SET end_time = ?, duration = TIMESTAMPDIFF(SECOND, start_time, ?), session_type = ? WHERE id = ?';
    await query(updateQuery, [end_time, end_time, session_type, session_id]);

    // Log when Pomodoro session ends for the user
    console.log(`Pomodoro session ended for userId: ${user_id}`);

    res.json({ message: 'Session ended successfully', end_time });
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});


app.get('/session-stats/pomodoro', async (req, res) => {
  const token = req.headers['authorization']; // Get token from the Authorization header
  if (!token || !token.startsWith('Bearer ')) {
    return res.status(403).json({ message: 'No token provided' });
  }

  try {
    const user_id = await getUserIdFromToken(token.split(' ')[1]); // Extract token value after 'Bearer '
    const selectQuery = 'SELECT * FROM pomodoro_date WHERE user_id = ? ORDER BY session_date DESC, start_time DESC';
    const result = await query(selectQuery, [user_id]);

    res.json(result);
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

app.put('/api/birthday', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; 
  const { birthday } = req.body;

  if (!token) {
    return res.status(401).json({ error: 'Authorization token is required' });
  }

  if (!birthday) {
    return res.status(400).json({ error: 'Birthday is required' });
  }

  try {
    const user_id = await getUserIdFromToken(token); 

    const query = 'UPDATE users SET birthday = ? WHERE id = ?';
    connection.query(query, [birthday, user_id], (err, result) => {
      if (err) {
        console.error('Error updating birthday:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Log the user and the date they entered the birthday
      const logDate = new Date().toISOString(); // Get the current date and time in ISO format
      console.log(`User with ID ${user_id} updated their birthday to ${birthday}`);

      res.status(200).json({ message: 'Birthday updated successfully' });
    });
  } catch (error) {
    console.error('Error processing token:', error);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});





const sendBirthdayEmail = async (user) => {
  const { email, unique_id, birthday } = user;

  const emailBody = `
  <html>
    <body style="font-family: Arial, sans-serif; background-color: #000000; padding: 20px;">
      <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
        <h2 style="color: #000000; text-align: center; font-size: 28px; font-weight: bold;">Happy Birthday, ${unique_id}!</h2>
        <p style="font-size: 16px; color: #000000; text-align: center; margin-top: 10px;">We at Edusify wish you a wonderful day full of joy and success. 🎉</p>
        <p style="font-size: 16px; color: #000000; text-align: center; margin-top: 10px;">May this year bring you all the happiness and achievements you deserve!</p>
        <div style="text-align: center; margin-top: 30px;">
          <a href="https://edusify.vercel.app" style="background-color: #000000; color: #ffffff; text-decoration: none; padding: 14px 20px; border-radius: 8px; font-size: 18px; font-weight: bold; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2); transition: background-color 0.3s;">
            Click for Surprise
          </a>
        </div>
      </div>
    </body>
  </html>
`;



  try {
    await transporter.sendMail({
      from: 'edusyfy@gmail.com', // Your sending email
      to: email,
      subject: `Happy Birthday, ${unique_id}! 🎉`,
      html: emailBody,
    });
    console.log(`Birthday email sent to ${unique_id} (${email})`); // Log the user who got the email
  } catch (error) {
    console.error('Error sending email:', error);
  }
};

// Function to check for users with today's birthday
const checkAndSendBirthdayEmails = async () => {
  const today = new Date().toISOString().split('T')[0]; // Get today's date in YYYY-MM-DD format

  try {
    // Fetch users with today's birthday from the database (make sure to replace with actual query function)
    const today = new Date();
    const month = today.getMonth() + 1; // JavaScript months are zero-indexed, so add 1
    const date = today.getDate();
    
    // Modify your query to match the month and day, ignoring the year
    const rows = await query('SELECT * FROM users WHERE MONTH(birthday) = ? AND DAY(birthday) = ?', [month, date]);
    

    rows.forEach((user) => {
      sendBirthdayEmail(user); // Send email to each user with today's birthday
    });
  } catch (error) {
    console.error('Error fetching users:', error);
  }
};

cron.schedule('0 0 * * *', checkAndSendBirthdayEmails); // '0 0 * * *' means 12:00 AM every day

app.post('/api/reports/generate', async (req, res) => {
  const { token } = req.body; // Token from the frontend

  try {
    const userId = await getUserIdFromToken(token); // Extract user ID from token

    // Check if a report was generated in the past week
    const lastReportQuery = `
      SELECT created_at 
      FROM reports 
      WHERE user_id = ? 
      ORDER BY created_at DESC LIMIT 1
    `;
    const lastReport = await new Promise((resolve, reject) => {
      connection.query(lastReportQuery, [userId], (err, results) => {
        if (err) return reject(err);
        resolve(results[0]);
      });
    });

    if (lastReport) {
      const lastReportDate = new Date(lastReport.created_at);
      const currentDate = new Date();
      const diffTime = currentDate - lastReportDate;
      const diffDays = diffTime / (1000 * 60 * 60 * 24); // Convert to days

      if (diffDays < 7) {
        return res.status(400).json({ error: 'You have already generated a report this week.' });
      }
    }

    // Fetch tasks for the user
    const tasksQuery = `
    SELECT created_at, due_date, completed_at 
    FROM tasks 
    WHERE user_id = ? 
    AND created_at >= CURDATE() - INTERVAL 15 DAY
  `;
    const tasks = await new Promise((resolve, reject) => {
      connection.query(tasksQuery, [userId], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    // Fetch quizzes for the user
    const quizzesQuery = `
    SELECT uq.score, uq.completed_at, q.title 
    FROM user_quizzes uq
    INNER JOIN quizzes q ON uq.quiz_id = q.id
    WHERE uq.user_id = ? 
    AND uq.completed_at >= CURDATE() - INTERVAL 15 DAY
  `;
  
    const quizzes = await new Promise((resolve, reject) => {
      connection.query(quizzesQuery, [userId], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    // Fetch Pomodoro sessions for the user
    const pomodoroQuery = `
    SELECT start_time, end_time, duration, session_date, session_type, created_at 
    FROM pomodoro_date 
    WHERE user_id = ? 
    AND created_at >= CURDATE() - INTERVAL 15 DAY
  `;
  
    const pomodoroSessions = await new Promise((resolve, reject) => {
      connection.query(pomodoroQuery, [userId], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });


// Check if there is enough data for the report (at least one condition should be met)
if (tasks.length >= 3 || pomodoroSessions.length >= 2 || quizzes.length >= 2) {
  // Proceed with generating the report
} else {
  return res.status(400).json({
    error: 'Not enough data to generate a report. You need at least 3 tasks, 2 Pomodoro sessions, or 2 quizzes.',
  });
}


    

    // Prepare the AI prompt
    const prompt = `
      Today's Date: ${new Date().toISOString().split('T')[0]}
      Analyze the following user data and generate a detailed report including user type, improvement areas, and strengths, and provide constructive feedback in an encouraging and empowering tone this reprot has to be shown to user directly so make it accordingly. 
      Format the report in JSON. The fields should include: "userType", "strengths", "improvementAreas", and a "summary".

      Tasks:
      ${JSON.stringify(tasks, null, 2)}

      Quizzes:
      ${JSON.stringify(quizzes, null, 2)}

      Pomodoro Sessions:
      ${JSON.stringify(pomodoroSessions, null, 2)}
    `;

    console.log('Generating report with prompt for userId:', userId);  // Log userId

    const chat = model.startChat({
      history: [
        { role: 'user', parts: [{ text: 'Hello' }] },
        { role: 'model', parts: [{ text: 'I can help generate a detailed user report!' }] },
      ],
    });

    const result = await chat.sendMessage(prompt);

    // Sanitize and parse the AI response
    const sanitizedResponse = result.response.text().replace(/```json|```|`/g, '').trim();

    let report;
    try {
      report = JSON.parse(sanitizedResponse);
    } catch (parseError) {
      console.error('Failed to parse JSON:', parseError);
      return res.status(500).json({ error: 'Invalid JSON response from the AI model' });
    }

    // Store the report in the database
    const insertReportQuery = `
      INSERT INTO reports (user_id, report) 
      VALUES (?, ?)
    `;
    await new Promise((resolve, reject) => {
      connection.query(insertReportQuery, [userId, JSON.stringify(report)], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    console.log('User report stored for userId:', userId);

    // Return the generated report
    res.json({ report });
  } catch (error) {
    console.error('Error generating report for userId:', req.body.token, error);  // Log error with userId
    let errorMessage = 'Failed to generate report';
    if (error.response) {
      errorMessage = `Error: ${error.response.status} - ${error.response.data?.message || error.response.statusText}`;
    } else if (error.message) {
      errorMessage = `Error: ${error.message}`;
    }
    res.status(500).json({ error: errorMessage });
  }
});



app.get('/api/reports', async (req, res) => {
  const token = req.headers.authorization; // Expecting `Bearer <token>` in the Authorization header

  if (!token) {
      return res.status(401).json({ error: 'Token is required' });
  }

  try {
      const userId = await getUserIdFromToken(token.split(' ')[1]); // Extract token after 'Bearer '
      const query = 'SELECT id, created_at FROM reports WHERE user_id = ? ORDER BY created_at DESC';
      connection.query(query, [userId], (err, results) => {
          if (err) {
              console.error('Error fetching reports:', err);
              return res.status(500).json({ error: 'Database error' });
          }
          const formattedResults = results.map((report) => ({
              id: report.id,
              created_at: new Date(report.created_at).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
              }),
          }));
          res.json({ reports: formattedResults });
      });
  } catch (err) {
      console.error('Error processing token:', err.message);
      res.status(401).json({ error: 'Invalid or expired token' });
  }
});

app.get('/api/reports/:id', (req, res) => {
  const { id } = req.params;
  const query = 'SELECT * FROM reports WHERE id = ?';
  connection.query(query, [id], (err, results) => {
      if (err) {
          console.error('Error fetching report:', err);
          return res.status(500).json({ error: 'Database error' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Report not found' });
      }

      const report = results[0];
      
      // Ensure strengths and improvementAreas are arrays
      report.strengths = JSON.parse(report.strengths || '[]');
      report.improvementAreas = JSON.parse(report.improvementAreas || '[]');

      res.json(report);
  });
});


app.post("/create-room", async (req, res) => {
  const { token, roomName, invitePermission } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    const roomId = `${roomName}-${Math.random().toString(36).substring(7)}`; // Generate unique room ID

    // Insert room into the rooms table
    const sql = `INSERT INTO rooms (name, created_by, invite_permission, room_id) VALUES (?, ?, ?, ?)`;
    connection.query(sql, [roomName, userId, invitePermission, roomId], (err, result) => {
      if (err) return res.status(500).send("Error creating room.");

      // Insert the creator (admin) into the room_members table
      const insertMemberSql = `INSERT INTO room_members (room_id, user_id) VALUES (?, ?)`;
      connection.query(insertMemberSql, [roomId, userId], (err, result) => {
        if (err) return res.status(500).send("Error adding admin to room.");

        // Log the room creation event
        console.log(`Room created successfully: Room ID = ${roomId}, Created By = ${userId}`);

        // Send response with success message and invite link
        res.send({
          message: "Room created successfully",
          inviteLink: `http://localhost:3000/room/invite/${roomId}`,
        });
      });
    });
  } catch (err) {
    console.error("Error creating room:", err);
    res.status(500).send("Invalid token.");
  }
});


app.post("/join-room", async (req, res) => {
  const { token, roomId } = req.body;

  try {
    const userId = await getUserIdFromToken(token);

    // Check if the user is already a member of any room
    const checkMembershipQuery = `SELECT * FROM room_members WHERE user_id = ?`;
    connection.query(checkMembershipQuery, [userId], (err, result) => {
      if (err) return res.status(500).send("Error checking room membership.");

      // If the user is already in a room, don't allow them to join another room
      if (result.length > 0) {
        return res.status(400).send("You are already in a room.");
      }

      // Otherwise, add the user to the new room
      const sql = `INSERT INTO room_members (room_id, user_id) VALUES (?, ?)`;
      connection.query(sql, [roomId, userId], (err, result) => {
        if (err) return res.status(500).send("Error joining room.");

        // Log the user joining the room
        console.log(`User ID = ${userId} successfully joined Room ID = ${roomId}`);

        res.send({ message: "Successfully joined the room!" });
      });
    });
  } catch (err) {
    console.error("Error processing the request:", err);
    res.status(500).send("Invalid token.");
  }
});

app.post("/check-user-in-room", async (req, res) => {
  const { token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);

    // Check if the user is already in any room
    const checkMembershipQuery = `SELECT * FROM room_members WHERE user_id = ?`;
    connection.query(checkMembershipQuery, [userId], (err, result) => {
      if (err) return res.status(500).send("Error checking room membership.");

      // If the user is in a room
      if (result.length > 0) {
        return res.json({ isInRoom: true });
      }

      res.json({ isInRoom: false });
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Invalid token.");
  }
});


// API route to get the leaderboard for a specific room
app.post('/api/roomLeaderboard', async (req, res) => {
  const { roomId } = req.body;

  try {
    // Step 1: Fetch user IDs from room_members where room_id = roomId
    const membersQuery = 'SELECT user_id FROM room_members WHERE room_id = ?';
    const members = await query(membersQuery, [roomId]);

    // Step 2: Fetch unique_id and points for each user
    const userIds = members.map(member => member.user_id);
    const userQuery = `
      SELECT u.id, u.unique_id, u.avatar, up.points
      FROM users u
      JOIN user_points up ON u.id = up.user_id
      WHERE u.id IN (?)`;
    const users = await query(userQuery, [userIds]);

    // Return the result as JSON
    res.json(users);
  } catch (err) {
    // Handle errors
    console.error('Error fetching leaderboard data:', err);
    res.status(500).json({ error: 'Failed to fetch leaderboard data' });
  }
});



// Fetch room details for the user
app.post("/get-room-details", async (req, res) => {
  const { token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);

    // Query to get the room details the user is part of
    const sql = `
      SELECT r.room_id, r.name, r.invite_permission
      FROM rooms r
      JOIN room_members rm ON r.room_id = rm.room_id
      WHERE rm.user_id = ?
      LIMIT 1;
    `;

    connection.query(sql, [userId], (err, result) => {
      if (err) return res.status(500).send("Error fetching room details.");
      if (result.length > 0) {
        res.send({ room: result[0] });
      } else {
        res.send({ room: null });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Invalid token.");
  }
});

app.post("/room-members-fetch", async (req, res) => {
  const { token, room_id } = req.body;

  try {
    const userId = await getUserIdFromToken(token);

    // Fetch room details
    const roomQuery = `SELECT id, name, invite_permission FROM rooms WHERE room_id = ?`;
    connection.query(roomQuery, [room_id], (roomErr, roomResult) => {
      if (roomErr) {
        console.error("Error fetching room details:", roomErr);
        return res.status(500).send("Error fetching room details.");
      }

      if (roomResult.length === 0) {
        return res.status(404).send("Room not found.");
      }

      const roomDetails = roomResult[0];

      // Fetch members
      const membersQuery = `SELECT users.id AS user_id, users.unique_id, users.avatar FROM room_members 
                            JOIN users ON room_members.user_id = users.id WHERE room_members.room_id = ?`;
      connection.query(membersQuery, [room_id], (membersErr, membersResult) => {
        if (membersErr) {
          console.error("Error fetching room members:", membersErr);
          return res.status(500).send("Error fetching members.");
        }

        // Send the final response without stories
        res.send({
          room: {
            ...roomDetails,
            members: membersResult, // Only members data
          },
        });
      });
    });
  } catch (err) {
    console.error("Error decoding token:", err);
    res.status(500).send("Invalid token.");
  }
});


app.post("/api/get-activities", async (req, res) => {
  const { roomId, filter } = req.body;
  try {
    // Step 1: Fetch user IDs for the given room
    const roomMembers = await query(
      "SELECT user_id FROM room_members WHERE room_id = ?",
      [roomId]
    );

    // Step 2: Build the user ID list
    const userIds = roomMembers.map((member) => member.user_id);

    // Step 3: Fetch activities based on the filter (today, week, lifetime)
    let activities = [];

    // Fetch tasks (added and completed)
    const tasks = await query(
      `SELECT user_id, created_at, completed_at FROM tasks WHERE user_id IN (?)`,
      [userIds]
    );
    tasks.forEach(async (task) => {
      const user = await query("SELECT unique_id FROM users WHERE id = ?", [task.user_id]);
      const userName = user[0].unique_id;
      
      if (task.created_at) {
        activities.push({
          description: `${userName} added a task`,
          time: task.created_at,
          type: "task_added",
        });
      }
      if (task.completed_at) {
        activities.push({
          description: `${userName} completed a task`,
          time: task.completed_at,
          type: "task_completed",
        });
      }
    });

    // Fetch Pomodoro sessions (started and ended)
    const pomodoroSessions = await query(
      `SELECT user_id, start_time, end_time FROM pomodoro_date WHERE user_id IN (?)`,
      [userIds]
    );
    pomodoroSessions.forEach(async (session) => {
      const user = await query("SELECT unique_id FROM users WHERE id = ?", [session.user_id]);
      const userName = user[0].unique_id;
      
      if (session.start_time) {
        activities.push({
          description: `${userName} started a Pomodoro session`,
          time: session.start_time,
          type: "pomodoro_started",
        });
      }
      if (session.end_time) {
        activities.push({
          description: `${userName} ended a Pomodoro session`,
          time: session.end_time,
          type: "pomodoro_ended",
        });
      }
    });

    // Fetch quiz scores
    const quizzes = await query(
      `SELECT user_id, quiz_id, score, completed_at FROM user_quizzes WHERE user_id IN (?)`,
      [userIds]
    );
    for (let quiz of quizzes) {
      const user = await query("SELECT unique_id FROM users WHERE id = ?", [quiz.user_id]);
      const userName = user[0]?.unique_id || "Unknown User";
      
      const quizTitle = await query("SELECT title FROM quizzes WHERE id = ?", [quiz.quiz_id]);
      
      // Check if quizTitle exists and has at least one row
      if (quizTitle.length > 0) {
        activities.push({
          description: `${userName} got a score of ${quiz.score} on quiz ${quizTitle[0].title}`,
          time: quiz.completed_at,
          type: "quiz_score",
        });
      } else {
        console.warn(`No quiz found for quiz_id: ${quiz.quiz_id}`);
      }
    }
    

    // Sort activities by time (most recent first)
    activities.sort((a, b) => new Date(b.time) - new Date(a.time));

    // Filter based on the chosen filter (today, week, lifetime)
    let filteredActivities = activities;
    if (filter === "today") {
      filteredActivities = filteredActivities.filter((activity) => {
        return (
          new Date(activity.time).toDateString() === new Date().toDateString()
        );
      });
    } else if (filter === "week") {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      filteredActivities = filteredActivities.filter((activity) => {
        return new Date(activity.time) > oneWeekAgo;
      });
    }

    res.json({ activities: filteredActivities });
  } catch (error) {
    console.error("Error fetching activities:", error);
    res.status(500).send("Error fetching activities");
  }
});

// Assuming you have Express and the 'query' helper function set up
app.get('/fetchRooms/user', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];  // Extract token
    if (!token) {
      return res.status(400).send('Token is missing');
    }
    
    const userId = await getUserIdFromToken(token);  // Get userId from token

    
    const roomsQuery = `
        SELECT rm.room_id, r.name 
        FROM room_members rm
        JOIN rooms r ON rm.room_id = r.room_id
        WHERE rm.user_id = ?;
    `;
    const rooms = await query(roomsQuery, [userId]);
    res.json(rooms);
  } catch (error) {
    console.error('Error fetching rooms:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Share quiz to a room
app.post('/shareQuiz/room', async (req, res) => {
  try {
    const { quizId, roomId } = req.body;
    const token = req.headers.authorization.split(' ')[1];  // Extract token from headers
    const userId = await getUserIdFromToken(token);  // Get userId from token

    const queryStr = `
        INSERT INTO room_resources (type, resource_id, user_id, room_id)
        VALUES ('quiz', ?, ?, ?);
    `;
    await query(queryStr, [quizId, userId, roomId]);  // Using the 'query' helper function
    res.status(200).send('Quiz shared successfully');
  } catch (error) {
    console.error('Error sharing quiz:', error);
    res.status(500).send('Internal Server Error');
  }
});


// Share note to a room (similar to quiz)
app.post('/shareNote-note', async (req, res) => {
  try {
      const { noteId, roomId } = req.body;
      const token = req.headers.authorization.split(' ')[1];  // Extract token from headers
      const userId = await getUserIdFromToken(token);  // Get userId from token

      const queryStr = `
          INSERT INTO room_resources (type, resource_id, user_id, room_id)
          VALUES ('note', ?, ?, ?);
      `;
      await query(queryStr, [noteId, userId, roomId]);  // Using the 'query' helper function
      res.status(200).send('Note shared successfully');
  } catch (error) {
      console.error('Error sharing note:', error);
      res.status(500).send('Internal Server Error');
  }
});

app.post('/api/roomResources', async (req, res) => {
  try {
      const { roomId, type } = req.body; // Get roomId and type (all, notes, quizzes) from the body
      const queryStr = `
          SELECT rr.id, rr.type, rr.resource_id, rr.created_at, u.unique_id as user_name
          FROM room_resources rr
          JOIN users u ON rr.user_id = u.id
          WHERE rr.room_id = ? ${type !== 'all' ? 'AND rr.type = ?' : ''}
      `;
      const queryParams = type !== 'all' ? [roomId, type] : [roomId];
      const resources = await query(queryStr, queryParams); // Run query to fetch resources

      for (let resource of resources) {
          if (resource.type === 'quiz') {
              const quizQuery = 'SELECT title FROM quizzes WHERE id = ?';
              const quiz = await query(quizQuery, [resource.resource_id]);
              resource.title = quiz.length > 0 ? quiz[0].title : 'Untitled Quiz';
          } else if (resource.type === 'note') {
              const noteQuery = 'SELECT title FROM flashcards WHERE id = ?';
              const note = await query(noteQuery, [resource.resource_id]);
              resource.title = note.length > 0 ? note[0].title : 'Untitled Note';
          }
      }

      res.status(200).json(resources);
  } catch (error) {
      console.error('Error fetching room resources:', error);
      res.status(500).send('Internal Server Error');
  }
});


app.post("/check-room", async (req, res) => {
  const { token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);


    const sql = `SELECT room_id FROM room_members WHERE user_id = ? LIMIT 1`;
    connection.query(sql, [userId], (err, result) => {
      if (err) {
        console.error("Error executing SQL query:", err); // Log SQL error
        return res.status(500).send("Error checking room.");
      }


      if (result.length > 0) {
        res.send({ roomId: result[0].room_id });
      } else {
        res.send({ roomId: null });
      }
    });
  } catch (err) {
    console.error("Error decoding token:", err); // Log token decoding error
    res.status(500).send("Invalid token.");
  }
});

// API route for leaving the room
app.post('/leaveRoom', async (req, res) => {
  const { token, room_id } = req.body;

  try {
    // Get userId from the token
    const userId = await getUserIdFromToken(token);

    // Use the promisified query to delete the user from the room
    const result = await query(
      'DELETE FROM room_members WHERE user_id = ? AND room_id = ?',
      [userId, room_id]
    );

    // If the deletion was successful, return a success message
    if (result.affectedRows > 0) {
      res.status(200).json({ success: true, message: 'User removed from the room' });
    } else {
      res.status(404).json({ success: false, message: 'User not found in this room' });
    }
  } catch (err) {
    console.error('Error removing user from room:', err);
    res.status(500).json({ success: false, message: 'Error leaving the room' });
  }
});

// Room progress endpoint
app.post('/room-progress', async (req, res) => {
  const { roomId } = req.body; // Get roomId from the body

  try {
    // Step 1: Get all user_ids in the room
    const roomMembers = await query('SELECT user_id FROM room_members WHERE room_id = ?', [roomId]);
    
    if (!roomMembers.length) {
      return res.status(404).json({ message: 'Room not found or no members in the room' });
    }

    const userIds = roomMembers.map(member => member.user_id);

    // Step 2: Fetch user details
    const users = await query('SELECT * FROM users WHERE id IN (?)', [userIds]);

    // Step 3: Get task progress
    const taskProgressPromises = userIds.map(async (userId) => {
      const totalTasks = await query('SELECT COUNT(*) AS total FROM tasks WHERE user_id = ?', [userId]);
      const completedTasks = await query('SELECT COUNT(*) AS completed FROM tasks WHERE user_id = ? AND completed = 1', [userId]);

      return {
        userId,
        totalTasks: totalTasks[0].total,
        completedTasks: completedTasks[0].completed,
      };
    });

    const taskProgress = await Promise.all(taskProgressPromises);

    // Step 4: Get flashcard progress
    const flashcardProgressPromises = userIds.map(async (userId) => {
      const flashcardSets = await query('SELECT id FROM flashcard_sets WHERE user_id = ?', [userId]);

      const flashcardProgressPromises = flashcardSets.map(async (set) => {
        const flashcards = await query('SELECT COUNT(*) AS known FROM flashcard WHERE set_id = ? AND status = "I know"', [set.id]);
        return flashcards[0].known;
      });

      const flashcardCounts = await Promise.all(flashcardProgressPromises);
      const totalKnownFlashcards = flashcardCounts.reduce((acc, count) => acc + count, 0);

      return { userId, totalKnownFlashcards };
    });

    const flashcardProgress = await Promise.all(flashcardProgressPromises);

    // Step 5: Get Pomodoro data
    const pomodoroProgressPromises = userIds.map(async (userId) => {
      const pomodoroData = await query('SELECT SUM(duration) AS totalDuration FROM pomodoro_date WHERE user_id = ?', [userId]);
      const totalDurationInHours = pomodoroData[0].totalDuration / 3600; // Convert seconds to hours

      return { userId, totalPomodoroHours: totalDurationInHours };
    });

    const pomodoroProgress = await Promise.all(pomodoroProgressPromises);

    // Combine all the progress data
    const roomProgress = users.map((user) => {
      const taskData = taskProgress.find(task => task.userId === user.id);
      const flashcardData = flashcardProgress.find(flashcard => flashcard.userId === user.id);
      const pomodoroData = pomodoroProgress.find(pomodoro => pomodoro.userId === user.id);

      return {
        userId: user.id,
        name: user.unique_id,
        totalTasks: taskData ? taskData.totalTasks : 0,
        completedTasks: taskData ? taskData.completedTasks : 0,
        totalKnownFlashcards: flashcardData ? flashcardData.totalKnownFlashcards : 0,
        totalPomodoroHours: pomodoroData ? pomodoroData.totalPomodoroHours : 0,
      };
    });

    // Respond with the room progress data
    res.json(roomProgress);

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/api/room_tasks/add', (req, res) => {
  const { room_id, title, description, due_date, priority } = req.body;

  if (!room_id || !title) {
    return res.status(400).json({ message: 'Room ID and Title are required' });
  }

  const query = `
    INSERT INTO room_tasks (room_id, title, description, due_date, priority)
    VALUES (?, ?, ?, ?, ?)
  `;

  connection.query(query, [room_id, title, description || null, due_date || null, priority || 'normal'], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error adding task' });
    }
    res.status(201).json({ message: 'Task added successfully', taskId: result.insertId });
  });
});

// API route to get tasks for a specific room
app.get('/api/room_tasks/get/:room_id', (req, res) => {
  const room_id = req.params.room_id;

  const query = 'SELECT * FROM room_tasks WHERE room_id = ?';

  connection.query(query, [room_id], (err, tasks) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching tasks' });
    }
    res.status(200).json(tasks);
  });
});

// API route to delete a task
app.delete('/api/room_tasks/delete/:taskId', (req, res) => {
  const taskId = req.params.taskId;

  const query = 'DELETE FROM room_tasks WHERE id = ?';

  connection.query(query, [taskId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error deleting task' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }
    res.status(200).json({ message: 'Task deleted successfully' });
  });
});


// Define storage for PDF uploads
const pdfStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, '/root/student-hub-backend-/public/'); // Save PDFs in a dedicated folder
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}${ext}`); // Timestamp to ensure unique file names
  },
});
// /root/student-hub-backend-/public/
// File filter for PDFs
const pdfFileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only PDFs are allowed.'), false);
  }
};

// Multer instance for PDF uploads
const uploadPDF = multer({
  storage: pdfStorage,
  fileFilter: pdfFileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }, // Limit file size to 10 MB
});

// API endpoint to upload PDF and generate flashcards
app.post('/api/flashcards/upload', uploadPDF.single('pdf'), async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const userId = await getUserIdFromToken(token); // Implement getUserIdFromToken to get user ID from token
    const { name, subject, topic } = req.body;

    // Create a new flashcard set in the database
    const setQuery = 'INSERT INTO flashcard_sets (name, subject, topic, user_id) VALUES (?, ?, ?, ?)';
    connection.query(setQuery, [name, subject, topic, userId], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: err.message });
      }

      const setId = results.insertId;

      // Extract text from the uploaded PDF file
      const pdfPath = req.file.path; // File path from multer
      const pdfText = await pdfParse(fs.readFileSync(pdfPath)).then((data) => data.text);
      if (!pdfText) {
        return res.status(400).json({ error: 'Failed to extract text from PDF' });
      }

      // Generate flashcards using AI logic
      const prompt = `Generate flashcards in JSON format based on the following text extracted from a PDF. Each flashcard should have a 'question' and 'answer' field. No additional formatting or Markdown:\n\n${pdfText}`;

      const chat = model.startChat({
        history: [
          {
            role: 'user',
            parts: [{ text: 'Hello' }],
          },
          {
            role: 'model',
            parts: [{ text: 'I can help generate flashcards for your study!' }],
          },
        ],
      });

      console.log('Generating flashcards From PDF');
      const result = await chat.sendMessage(prompt);

      // Sanitize and parse the AI response
      const sanitizedResponse = result.response.text().replace(/```json|```|`/g, '').trim();
      let flashcards;
      try {
        flashcards = JSON.parse(sanitizedResponse);
      } catch (parseError) {
        console.error('Failed to parse JSON:', parseError);
        return res.status(500).json({ error: 'Invalid JSON response from the AI model' });
      }

      // Prepare flashcards data to insert into the database
      const flashcardsData = flashcards.map(({ question, answer }) => [setId, question.trim(), answer.trim()]);
      connection.query(
        'INSERT INTO flashcard (set_id, question, answer) VALUES ?',
        [flashcardsData],
        (err) => {
          if (err) {
            console.error('Error inserting flashcards:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          // Optionally delete the file after processing
          fs.unlink(pdfPath, (unlinkErr) => {
            if (unlinkErr) {
              console.error('Error deleting file:', unlinkErr);
            }
          });

          res.json({ flashcardSetId: setId, flashcards });
        }
      );
    });
  } catch (error) {
    console.error('Error processing PDF upload:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint for PDF upload and flashcard generation
app.post('/api/flashcards/upload/set-created', uploadPDF.single('pdf'), async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // Extract user ID from token
    const userId = await getUserIdFromToken(token); // Implement your own token handling logic
    const { set_id } = req.body; // Set ID is passed from the frontend

    // Make sure we have a valid set_id
    if (!set_id) {
      return res.status(400).json({ error: 'Missing set_id' });
    }

    // Extract text from the uploaded PDF
    const pdfPath = req.file.path; // File path from multer
    const pdfText = await pdfParse(fs.readFileSync(pdfPath)).then((data) => data.text);
    
    if (!pdfText) {
      return res.status(400).json({ error: 'Failed to extract text from PDF' });
    }

    // Generate flashcards using AI logic based on PDF text
    const prompt = `Generate flashcards in JSON format based on the following text extracted from a PDF. Each flashcard should have a 'question' and 'answer' field. No additional formatting or Markdown:\n\n${pdfText}`;
    
    const chat = model.startChat({
      history: [
        { role: 'user', parts: [{ text: 'Generate flashcards from this PDF text' }] },
      ],
    });

    const result = await chat.sendMessage(prompt);

    // Sanitize and parse the AI response
    const sanitizedResponse = result.response.text().replace(/```json|```|`/g, '').trim();
    let flashcards;
    try {
      flashcards = JSON.parse(sanitizedResponse);
    } catch (parseError) {
      console.error('Failed to parse JSON:', parseError);
      return res.status(500).json({ error: 'Invalid JSON response from the AI model' });
    }

    // Insert flashcards into the database and associate them with the set_id
    const flashcardsData = flashcards.map(({ question, answer }) => [set_id, question.trim(), answer.trim()]);
    
    connection.query(
      'INSERT INTO flashcard (set_id, question, answer) VALUES ?',
      [flashcardsData],
      (err) => {
        if (err) {
          console.error('Error inserting flashcards:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        // Optionally delete the file after processing
        fs.unlink(pdfPath, (unlinkErr) => {
          if (unlinkErr) {
            console.error('Error deleting file:', unlinkErr);
          }
        });

        // Send response with the generated flashcards
        res.json({ flashcardSetId: set_id, flashcards });
      }
    );
  } catch (error) {
    console.error('Error processing PDF upload:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/quiz/generate-from-pdf', uploadPDF.single('pdf'), async (req, res) => {
  const { subject, topic, token } = req.body;

  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);

    // Step 2: Extract text from the PDF
    const pdfPath = req.file.path;
    const pdfText = await pdfParse(fs.readFileSync(pdfPath)).then((data) => data.text);

    if (!pdfText) {
      return res.status(400).json({ error: 'Failed to extract text from PDF' });
    }

    // Step 3: Define AI prompt
    const prompt = `
      Generate a valid JSON array of 15 multiple-choice questions from the following text:
      - Text: "${pdfText}"

      Each question must strictly follow this format:
      [
        {
          "question": "string",
          "options": ["string", "string", "string", "string"],
          "correct_answer": "string"
        }
      ]

      Rules:
      1. Return only the JSON array without any explanations or comments.
      2. Ensure each question and options are meaningful and unique.
      3. Format the JSON properly.
    `.trim();

    // Step 4: AI Integration and retry logic
    const generateQuizWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          const chat = model.startChat({ history: [] });
          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
          let quizQuestions;

          try {
            quizQuestions = JSON.parse(sanitizedResponse);
          } catch (parseError) {
            throw new Error('Invalid JSON response from the AI model');
          }

          return quizQuestions;
        } catch (error) {
          attempts++;
          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate quiz after multiple attempts');
          }
          await new Promise((resolve) => setTimeout(resolve, 2000)); // Retry delay
        }
      }
    };

    const quizQuestions = await generateQuizWithRetry();

    // Step 5: Insert into the database
    const title = `${subject} - ${topic} Quiz (PDF)`;
    const description = `Quiz on ${subject} - ${topic} (Generated from PDF)`;
    const [quizResult] = await connection.promise().query(
      'INSERT INTO quizzes (title, description, creator_id) VALUES (?, ?, ?)',
      [title, description, userId]
    );
    const quizId = quizResult.insertId;

    for (const question of quizQuestions) {
      const [questionResult] = await connection.promise().query(
        'INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)',
        [quizId, question.question]
      );
      const questionId = questionResult.insertId;

      for (const option of question.options) {
        const isCorrect = option === question.correct_answer;
        await connection.promise().query(
          'INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)',
          [questionId, option, isCorrect]
        );
      }
    }
    console.log('Quiz generated from PDF and saved successfully');
    res.json({ message: 'Quiz generated successfully from PDF', quizId });
  } catch (error) {
    console.error('Error generating quiz from PDF:', error);
    res.status(500).json({ error: 'Error generating quiz from PDF' });
  }
});

app.post('/api/quiz/generate/from-notes', upload.none(), async (req, res) => {
  const { subject, notes, token } = req.body;

  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);

    // Step 2: Define a refined prompt to ensure proper quiz generation based on the notes
    const prompt = `Generate a valid JSON array of 15 multiple-choice questions based on the following notes:
      - Notes: ${notes}
      
      
      Each question must strictly follow this format:
      [
        {
          "question": "string",
          "options": ["string", "string", "string", "string"],
          "correct_answer": "string"
        }
      ]

      Rules:
      1. Return only the JSON array without any explanations or comments.
      2. Ensure each question and options are meaningful and unique.
      3. Format the JSON properly.
  `;

    console.log('Generating quiz with Notes');

    // Step 4: AI Integration and retry logic
    const generateQuizWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          const chat = model.startChat({ history: [] });
          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
          let quizQuestions;

          try {
            quizQuestions = JSON.parse(sanitizedResponse);
          } catch (parseError) {
            throw new Error('Invalid JSON response from the AI model');
          }

          return quizQuestions;
        } catch (error) {
          attempts++;
          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate quiz after multiple attempts');
          }
          await new Promise((resolve) => setTimeout(resolve, 2000)); // Retry delay
        }
      }
    };

    const quizQuestions = await generateQuizWithRetry();

    // Step 6: Insert quiz details into the database
    const title = `${subject} Quiz`; // Use the subject from the frontend
    const description = `Quiz on ${subject}`; // Use subject for description as well
    const [quizResult] = await connection.promise().query(
      'INSERT INTO quizzes (title, description, creator_id) VALUES (?, ?, ?)',
      [title, description, userId]
    );
    const quizId = quizResult.insertId;

    // Step 7: Insert questions and their options into the database
    for (const question of quizQuestions) {
      const [questionResult] = await connection.promise().query(
        'INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)',
        [quizId, question.question]
      );
      const questionId = questionResult.insertId;

      for (const option of question.options) {
        const isCorrect = option === question.correct_answer;
        await connection.promise().query(
          'INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)',
          [questionId, option, isCorrect]
        );
      }
    }

    // Step 8: Return the generated quiz details
    res.json({ message: 'Quiz generated successfully', quizId });
  } catch (error) {
    console.error('Error generating quiz:', error);
    res.status(500).json({ error: 'Error generating quiz' });
  }
});

app.post('/api/quiz/generate/from-magic', upload.none(), async (req, res) => {
  const { subject, notes, token } = req.body;

  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);

    // Step 2: Define a refined prompt to ensure proper quiz generation based on the notes
    const prompt = `Generate a valid JSON array of 15 multiple-choice questions based on the following notes:
      - Notes: ${notes}
      
      
      Each question must strictly follow this format:
      [
        {
          "question": "string",
          "options": ["string", "string", "string", "string"],
          "correct_answer": "string"
        }
      ]

      Rules:
      1. Return only the JSON array without any explanations or comments.
      2. Ensure each question and options are meaningful and unique.
      3. Format the JSON properly.
  `;

    console.log('Generating quiz with Magic');

    // Step 4: AI Integration and retry logic
    const generateQuizWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          const chat = model.startChat({ history: [] });
          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
          let quizQuestions;

          try {
            quizQuestions = JSON.parse(sanitizedResponse);
          } catch (parseError) {
            throw new Error('Invalid JSON response from the AI model');
          }

          return quizQuestions;
        } catch (error) {
          attempts++;
          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate quiz after multiple attempts');
          }
          await new Promise((resolve) => setTimeout(resolve, 2000)); // Retry delay
        }
      }
    };

    const quizQuestions = await generateQuizWithRetry();

    // Step 6: Insert quiz details into the database
    const title = `${subject} Quiz`; // Use the subject from the frontend
    const description = `Quiz on ${subject}`; // Use subject for description as well
    const [quizResult] = await connection.promise().query(
      'INSERT INTO quizzes (title, description, creator_id) VALUES (?, ?, ?)',
      [title, description, userId]
    );
    const quizId = quizResult.insertId;

    // Step 7: Insert questions and their options into the database
    for (const question of quizQuestions) {
      const [questionResult] = await connection.promise().query(
        'INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)',
        [quizId, question.question]
      );
      const questionId = questionResult.insertId;

      for (const option of question.options) {
        const isCorrect = option === question.correct_answer;
        await connection.promise().query(
          'INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)',
          [questionId, option, isCorrect]
        );
      }
    }


    const magicUsageQuery = 'INSERT INTO magic_usage (user_id, type) VALUES (?, ?)';
    await connection.promise().query(magicUsageQuery, [userId, 'quiz_generation']);

    // Step 8: Return the generated quiz details
    res.json({ message: 'Quiz generated successfully', quizId });
  } catch (error) {
    console.error('Error generating quiz:', error);
    res.status(500).json({ error: 'Error generating quiz' });
  }
});

app.post('/complete-flashcard-quiz', async (req, res) => {
  const { token } = req.body;
  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);

    // Update points for the user
    await query('UPDATE user_points SET points = points + 5 WHERE user_id = ?', [userId]);

    res.status(200).json({ message: 'User points updated successfully' });
  } catch (error) {
    console.error('Error completing flashcard quiz:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



app.post('/api/flashcards/generate-from-notes', async (req, res) => {
  const { headings, subject } = req.body; // Accept headings and subject
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const userId = await getUserIdFromToken(token); // Fetch user ID from token

    // Validate input
    if (!headings || !subject) {
      return res.status(400).json({ error: 'Headings and subject are required' });
    }

    // Create a new flashcard set in the database
    const setQuery = 'INSERT INTO flashcard_sets (name, subject, user_id, topic) VALUES (?, ?, ?, ?)';
    connection.query(setQuery, [subject, subject, userId, subject], async (err, results) => {
      if (err) {
        console.error('Database error (flashcard_sets):', err);
        return res.status(500).json({ error: 'Failed to create flashcard set' });
      }

      const setId = results.insertId; // Get the inserted flashcard set ID

      // Define the AI prompt for generating flashcards based on the notes
      const prompt = `Generate a valid JSON array of flashcards based on the following notes:
      - Notes: ${headings}

      Each flashcard should follow this format:
      [
        {
          "question": "string",
          "answer": "string"
        }
      ]

      Rules:
      1. Ensure the flashcards are accurate, concise, and relevant to the subject: ${subject}.
      2. Return only the JSON array without any explanations or comments.
      3. Format the JSON properly.`;

      console.log('Generating flashcards with Notes');

      // Step 4: AI Integration and retry logic for flashcard generation
      const generateFlashcardsWithRetry = async () => {
        let attempts = 0;
        const MAX_RETRIES = 3;

        while (attempts < MAX_RETRIES) {
          try {
            const chat = model.startChat({ history: [] });
            const result = await chat.sendMessage(prompt);
            const rawResponse = await result.response.text();

            const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
            let flashcards;

            try {
              flashcards = JSON.parse(sanitizedResponse);
            } catch (parseError) {
              throw new Error('Invalid JSON response from the AI model');
            }

            return flashcards;
          } catch (error) {
            attempts++;
            if (attempts === MAX_RETRIES) {
              throw new Error('Failed to generate flashcards after multiple attempts');
            }
            await new Promise((resolve) => setTimeout(resolve, 2000)); // Retry delay
          }
        }
      };

      // Get the flashcards by calling the retry function
      const flashcards = await generateFlashcardsWithRetry();

      // Prepare data for database insertion
      const flashcardsData = flashcards
        .filter(card => card.question?.trim() && card.answer?.trim())
        .map(({ question, answer }) => [setId, question.trim(), answer.trim()]);

      if (flashcardsData.length === 0) {
        return res.status(400).json({ error: 'No valid flashcards generated' });
      }

      // Insert the generated flashcards into the database
      connection.query(
        'INSERT INTO flashcard (set_id, question, answer) VALUES ?',
        [flashcardsData],
        (err) => {
          if (err) {
            console.error('Error inserting flashcards:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          res.json({ flashcardSetId: setId, flashcards });
        }
      );
    });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/flashcards/generate-from-magic', async (req, res) => {
  const { headings, subject } = req.body; // Accept headings and subject
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const userId = await getUserIdFromToken(token); // Fetch user ID from token

    // Validate input
    if (!headings || !subject) {
      return res.status(400).json({ error: 'Headings and subject are required' });
    }

    // Create a new flashcard set in the database
    const setQuery = 'INSERT INTO flashcard_sets (name, subject, user_id, topic) VALUES (?, ?, ?, ?)';
    connection.query(setQuery, [subject, subject, userId, subject], async (err, results) => {
      if (err) {
        console.error('Database error (flashcard_sets):', err);
        return res.status(500).json({ error: 'Failed to create flashcard set' });
      }

      const setId = results.insertId; // Get the inserted flashcard set ID

      // Define the AI prompt for generating flashcards based on the notes
      const prompt = `Generate a valid JSON array of flashcards based on the following notes:
      - Notes: ${headings}

      Each flashcard should follow this format:
      [
        {
          "question": "string",
          "answer": "string"
        }
      ]

      Rules:
      1. Ensure the flashcards are accurate, concise, and relevant to the subject: ${subject}.
      2. Return only the JSON array without any explanations or comments.
      3. Format the JSON properly.`;

      console.log('Generating flashcards with magic');

      // Step 4: AI Integration and retry logic for flashcard generation
      const generateFlashcardsWithRetry = async () => {
        let attempts = 0;
        const MAX_RETRIES = 3;

        while (attempts < MAX_RETRIES) {
          try {
            const chat = model.startChat({ history: [] });
            const result = await chat.sendMessage(prompt);
            const rawResponse = await result.response.text();

            const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
            let flashcards;

            try {
              flashcards = JSON.parse(sanitizedResponse);
            } catch (parseError) {
              throw new Error('Invalid JSON response from the AI model');
            }

            return flashcards;
          } catch (error) {
            attempts++;
            if (attempts === MAX_RETRIES) {
              throw new Error('Failed to generate flashcards after multiple attempts');
            }
            await new Promise((resolve) => setTimeout(resolve, 2000)); // Retry delay
          }
        }
      };

      // Get the flashcards by calling the retry function
      const flashcards = await generateFlashcardsWithRetry();

      // Prepare data for database insertion
      const flashcardsData = flashcards
        .filter(card => card.question?.trim() && card.answer?.trim())
        .map(({ question, answer }) => [setId, question.trim(), answer.trim()]);

      if (flashcardsData.length === 0) {
        return res.status(400).json({ error: 'No valid flashcards generated' });
      }

      // Insert the generated flashcards into the database
      connection.query(
        'INSERT INTO flashcard (set_id, question, answer) VALUES ?',
        [flashcardsData],
        (err) => {
          if (err) {
            console.error('Error inserting flashcards:', err);
            return res.status(500).json({ error: 'Database error' });
          }
           // Log the magic usage (without linking to flashcard_sets)
        const magicUsageQuery = 'INSERT INTO magic_usage (user_id, type) VALUES (?, ?)';
        connection.query(magicUsageQuery, [userId, 'flashcard_generation'], (err) => {
          if (err) {
            console.error('Error logging magic usage:', err);
          }
        });


          res.json({ flashcardSetId: setId, flashcards });
        }
      );
    });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const getStats = async (token) => {
  try {
    // Get userId from the token
    const userId = await getUserIdFromToken(token);

    if (!userId) {
      throw new Error('User not found');
    }

    // Fetch completed tasks
    const tasksCompleted = await query('SELECT COUNT(*) AS count FROM tasks WHERE completed = 1 AND user_id = ?', [userId]);

    // Calculate total duration from Pomodoro data in seconds
    const pomodoroDurationRows = await query('SELECT duration FROM pomodoro_date WHERE user_id = ?', [userId]);

    // Sum up the durations and convert from seconds to hours
    const totalPomodoroDuration = pomodoroDurationRows.reduce((sum, row) => sum + row.duration, 0) / 3600; // convert seconds to hours

    // Count Pomodoro sessions
    const pomodoroSessions = await query('SELECT COUNT(*) AS count FROM pomodoro_date WHERE user_id = ?', [userId]);

    // Fetch the setIds from flashcard_sets
    const flashcardSets = await query('SELECT id FROM flashcard_sets WHERE user_id = ?', [userId]);
    const setIds = flashcardSets.map(set => set.id);

    // If no flashcard sets exist for the user, return 0 mastered flashcards
    if (setIds.length === 0) {
      return {
        tasksCompleted: tasksCompleted[0].count,
        totalPomodoroDuration, // in hours
        pomodoroSessions: pomodoroSessions[0].count,
        flashcardsMastered: 0,
        leaderboardPosition: null, // Position will be null if no sets exist
      };
    }

    // Fetch mastered flashcards by setId
    const flashcardsMastered = await query(
      'SELECT COUNT(*) AS count FROM flashcard WHERE set_id IN (?) AND status = "I Know"',
      [setIds]
    );

    // Fetch user points and calculate leaderboard position
    const userPoints = await query('SELECT points FROM user_points WHERE user_id = ?', [userId]);

    if (!userPoints || userPoints.length === 0) {
      throw new Error('User points not found');
    }

    const userPointsValue = userPoints[0].points;

    // Fetch all user points and sort them in descending order
    const allUserPoints = await query('SELECT user_id, points FROM user_points ORDER BY points DESC');

    // Find the position by comparing user's points with all other users
    const leaderboardPosition = allUserPoints.findIndex(user => user.points === userPointsValue) + 1;

    return {
      tasksCompleted: tasksCompleted[0].count,
      totalPomodoroDuration, // in hours
      pomodoroSessions: pomodoroSessions[0].count,
      flashcardsMastered: flashcardsMastered[0].count,
      leaderboardPosition,
    };
  } catch (error) {
    console.error('Error fetching stats:', error);
    return null;
  }
};

// API route to get stats based on token
app.get('/api/stats', async (req, res) => {
  try {
    // Get the token from query parameters or headers
    const token = req.query.token || req.headers['authorization'];

    if (!token) {
      return res.status(400).json({ message: 'Token is required' });
    }

    // Call the function to get stats
    const stats = await getStats(token);

    if (!stats) {
      return res.status(500).json({ message: 'Error fetching stats' });
    }

    // Return the stats as a response
    return res.status(200).json(stats);
  } catch (error) {
    console.error('Error in /stats route:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post("/room/posts/add/:roomId", upload.single("image"), async (req, res) => {
  try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
          return res.status(401).send({ message: "Authorization token missing." });
      }

      const userId = await getUserIdFromToken(token);
      const roomId = req.params.roomId;
      const { type, content } = req.body;

      if (!["text", "image"].includes(type)) { // Removed "poll"
          return res.status(400).send({ message: "Invalid post type." });
      }

      let postContent = content;
      if (type === "image" && req.file) {
          postContent = `${req.file.filename}`;
      } else if (type === "image" && !req.file) {
          return res.status(400).send({ message: "Image is required for image post type." });
      }

      const query = `
          INSERT INTO room_posts (user_id, room_id, type, content)
          VALUES (?, ?, ?, ?)
      `;
      connection.query(query, [userId, roomId, type, postContent], (err) => {
          if (err) {
              console.error("Database Insert Error: ", err);
              return res.status(500).send({ message: "Error creating post." });
          }
          res.status(201).send({ message: "Post created successfully." });
      });
  } catch (error) {
      console.error("Server Error: ", error);
      res.status(500).send({ message: "Internal server error." });
  }
});

// Handle post deletion
app.delete("/room/posts/delete/:postId", async (req, res) => {
  const { postId } = req.params;

  // Ensure the user is authorized to delete the post
  const token = req.headers['authorization'].split(' ')[1];
  if (!token) return res.status(401).send({ message: 'No token provided' });

  try {

    const userId = await getUserIdFromToken(token);

    // First, check if the post exists and belongs to the user
    const [post] = await connection.promise().query(
      `SELECT * FROM room_posts WHERE id = ?`, [postId]
    );

    if (!post) {
      return res.status(404).send({ message: 'Post not found' });
    }


    // Proceed to delete the post
    await connection.promise().query(
      `DELETE FROM room_posts WHERE id = ?`, [postId]
    );

    res.status(200).send({ message: 'Post deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Error deleting post' });
  }
});


// Fetch posts for a room
app.get("/room/posts/fetch/:roomId", async (req, res) => {
  const { roomId } = req.params;

  const query = `
    SELECT 
      rp.id AS post_id, 
      rp.type, 
      rp.content, 
      rp.created_at, 
      u.unique_id AS user_name,
      rp.user_id  -- Include user_id from the post
    FROM 
      room_posts rp
    JOIN 
      users u ON rp.user_id = u.id
    WHERE 
      rp.room_id = ?
    ORDER BY 
      rp.created_at DESC
  `;

  connection.query(query, [roomId], (err, results) => {
    if (err) return res.status(500).send({ message: "Error fetching posts." });
    res.status(200).send(results);
  });
});


app.get('/user-profile/:user_id', async (req, res) => {
  const user_id = req.params.user_id;

  try {
    // Query to fetch user details (username, bio, avatar)
    const userResult = await query('SELECT unique_id, user_name, bio, avatar FROM users WHERE id = ?', [user_id]);

    if (userResult.length === 0) {
      return res.status(404).send({ message: 'User not found' });
    }

    const user = userResult[0];

    // Fetch room name using room_id
    const roomResult = await query(
      'SELECT r.name FROM room_members rm JOIN rooms r ON rm.room_id = r.room_id WHERE rm.user_id = ?',
      [user_id]
    );
    const room = roomResult.length > 0 ? roomResult[0].name : 'No room';

    // Fetch points from user_points table
    const pointsResult = await query(
      'SELECT points FROM user_points WHERE user_id = ?',
      [user_id]
    );
    const points = pointsResult.length > 0 ? pointsResult[0].points : 0;

    // Fetch Pomodoro duration in hours (rounding to 2 decimal places)
    const pomodoroResult = await query(
      'SELECT SUM(duration) AS total_seconds FROM pomodoro_date WHERE user_id = ?',
      [user_id]
    );
    const pomodoroHours = pomodoroResult[0].total_seconds ? (pomodoroResult[0].total_seconds / 3600).toFixed(2) : 0;

    // Fetch user quizzes data: highest score and quizzes attended
    const quizzesResult = await query(
      'SELECT MAX(score) AS highest_score, COUNT(*) AS quizzes_attended FROM user_quizzes WHERE user_id = ?',
      [user_id]
    );
    const highestQuizScore = quizzesResult[0].highest_score || 0;
    const quizzesAttended = quizzesResult[0].quizzes_attended || 0;

    // Fetch number of completed tasks
    const tasksResult = await query(
      'SELECT COUNT(*) AS completed_tasks FROM tasks WHERE user_id = ? AND completed = "1"',
      [user_id]
    );
    const completedTasks = tasksResult[0].completed_tasks || 0;

    // Fetch subjects for the user (correct query with user_subjects)
    const subjectsResult = await query(
      'SELECT s.name FROM subjects s JOIN subjects us ON s.id = us.id WHERE us.user_id = ?',
      [user_id]
    );
    const topSubjects = subjectsResult.map((subject) => subject.name);

    // Prepare final response
    const response = {
      user_id: user.unique_id,
      name: user.user_name,
      bio: user.bio,
      avatar: user.avatar,
      room,
      leaderboardPoints: points,
      highestQuizScore,
      pomodoroHours,
      completedTasks,
      quizzesAttended,
      topSubjects
    };

    // Send the response
    res.json(response);
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});


// Endpoint to send friend request
app.post('/api/friend/request', async (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];// Assuming token is passed as Bearer token in the Authorization header
  const { profileUserId } = req.body;
  try {
    // Get current user ID from token
    const currentUserId = await getUserIdFromToken(token);

    // Check if the current user is trying to send a request to themselves
  if (currentUserId === profileUserId) {
     return res.status(400).json({ message: 'Cannot send a friend request to yourself' });
   }

    // Check if a friend request already exists and is pending
    const existingRequest = await query(
      'SELECT * FROM friend_requests WHERE sender_id = ? AND receiver_id = ? AND status = "pending"',
      [currentUserId, profileUserId]
    );

    if (existingRequest.length > 0) {
      return res.status(400).json({ message: 'Friend request already sent' });
    }

    // Insert friend request into the database
    await query(
      'INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (?, ?, "pending")',
      [currentUserId, profileUserId]
    );

    res.status(200).json({ message: 'Friend request sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error sending friend request' });
  }
});

// Endpoint to accept or decline friend request
app.post('/api/friend/response', async (req, res) => {
  const { token, profileUserId, action } = req.body;

  try {
    // Get current user ID from token
    const currentUserId = await getUserIdFromToken(token);

    // Update the friend request status based on the action
    let status = 'pending';
    if (action === 'accept') {
      status = 'accepted';
      // Add both users to the friends table
      await query(
        'INSERT INTO friends (user_id_1, user_id_2) VALUES (?, ?), (?, ?)',
        [currentUserId, profileUserId, profileUserId, currentUserId]
      );
    } else if (action === 'decline') {
      status = 'declined';
    }

    // Update the friend request status in the database
    await query(
      'UPDATE friend_requests SET status = ? WHERE sender_id = ? AND receiver_id = ?',
      [status, profileUserId, currentUserId]
    );

    res.status(200).json({ message: `Friend request ${action}ed successfully` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error processing friend request' });
  }
});


// Endpoint to check the status of the friend request
app.get('/api/friend/status/:profileUserId', async (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];// Assuming token is passed as Bearer token in the Authorization header
  const { profileUserId } = req.params;

  if (!token) {
    return res.status(400).json({ message: 'Token is required' });
  }

  try {
    const currentUserId = await getUserIdFromToken(token);

    // Check if there's an existing friend request from the current user to the profile user
    const requestStatus = await query(
      'SELECT status FROM friend_requests WHERE sender_id = ? AND receiver_id = ?',
      [currentUserId, profileUserId]
    );

    // If a request exists from the current user to the profile user, return the status
    if (requestStatus.length > 0) {
      return res.status(200).json({ status: requestStatus[0].status });
    }

    // Check if there's a reverse friend request from the profile user to the current user
    const reverseRequestStatus = await query(
      'SELECT status FROM friend_requests WHERE sender_id = ? AND receiver_id = ?',
      [profileUserId, currentUserId]
    );

    // If a request exists from the profile user to the current user, return the status
    if (reverseRequestStatus.length > 0) {
      return res.status(200).json({ status: reverseRequestStatus[0].status });
    }

    // If no request exists, return 'none'
    res.status(200).json({ status: 'none' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving friend request status' });
  }
});


app.get('/api/friends-dashboard', async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
    const userId = await getUserIdFromToken(token); // Fetch user ID from token

    // Fetch pending friend requests for the current user
    const friendRequests = await query(
      'SELECT * FROM friend_requests WHERE receiver_id = ? AND status = "pending"',
      [userId]
    );

    // Fetch the details of each sender (unique_id, avatar, and id)
    const detailedRequests = await Promise.all(friendRequests.map(async (request) => {
      const senderData = await query(
        'SELECT unique_id, avatar, id FROM users WHERE id = ?',
        [request.sender_id]
      );
      return {
        ...request,
        sender_unique_id: senderData[0].unique_id,
        sender_avatar: senderData[0].avatar,
        sender_id: senderData[0].id,
      };
    }));

    // Fetch all friends for the current user
    const friends = await query(
      'SELECT * FROM friends WHERE user_id_1 = ? OR user_id_2 = ?',
      [userId, userId]
    );

    // Fetch the friend details (avatar and unique ID) for each friend
    const friendsList = await Promise.all(friends.map(async (friend) => {
      const otherUserId = friend.user_id_1 === userId ? friend.user_id_2 : friend.user_id_1;

      // Fetch the friend's unique ID and avatar from the users table
      const userData = await query(
        'SELECT unique_id, avatar FROM users WHERE id = ?',
        [otherUserId]
      );

      return {
        id: otherUserId,
        avatar: userData[0].avatar,
        uniqueId: userData[0].unique_id,
      };
    }));

    res.json({
      friendRequests: detailedRequests,
      friends: friendsList,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error fetching friends and requests' });
  }
});

// API to fetch user resources
app.get('/user-resources/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // Fetch notes (flashcards)
    const notes = await query('SELECT * FROM flashcards WHERE user_id = ? AND is_public = true', [userId]);

    // Fetch quizzes
    const quizzes = await query('SELECT * FROM quizzes WHERE creator_id = ?', [userId]);

    // Send the combined result
    res.json({ notes, quizzes });
  } catch (error) {
    console.error('Error fetching user resources:', error);
    res.status(500).json({ message: 'Error fetching user resources' });
  }
});

// Route to end the current event
const transporterSec = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: 'edusiyfy@gmail.com',
      pass: 'hvht twsf ejma juft',
  },
});

// Route to fetch all journals
app.get('/journals', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Assuming token is in 'Bearer token'

  if (!token) {
    return res.status(401).json({ error: 'Authorization token missing' });
  }

  try {
    const userId = await getUserIdFromToken(token);
    const journals = await query('SELECT * FROM journals WHERE user_id = ?', [userId]);

    if (journals.length === 0) {
      return res.json({ message: 'No journals found' });
    }

    res.json(journals);
  } catch (error) {
    console.error('Error fetching journals:', error);
    res.status(500).json({ error: 'Failed to fetch journals' });
  }
});

// Save study data
app.post('/api/save-study-data', (req, res) => {
  const {
      educationLevel,
      grades,
      dailyStudyTime,
      studyPerformance,
      subjects,
      goals,
      challenges
  } = req.body;

  const query = `
      INSERT INTO study_plans 
      (education_level, grades, daily_study_time, study_performance, subjects, goals, challenges) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  connection.query(
      query,
      [educationLevel, grades, dailyStudyTime, studyPerformance, JSON.stringify(subjects), goals, challenges],
      (err, result) => {
          if (err) {
              console.error(err);
              res.status(500).send('Error saving data');
          } else {
              res.send({ message: 'Study data saved successfully!', id: result.insertId });
          }
      }
  );
});

// Route to send emails to users
app.post('/send-emails/selected-users/admin', async (req, res) => {
  const { content, subject, selectedUsers } = req.body;

  try {
      let users;

      if (selectedUsers && selectedUsers.length > 0) {
          // Fetch only the selected users
          const placeholders = selectedUsers.map(() => '?').join(',');
          users = await query(`SELECT email, unique_id FROM users WHERE unique_id IN (${placeholders})`, selectedUsers);
      } else {
          // Fetch all users if no specific users are selected
          users = await query('SELECT email, unique_id FROM users', []);
      }

      const emailsToSend = users.map((user) => {
          const personalizedContent = content.replace(/{{name}}/g, user.unique_id);

          return {
              from: 'edusiyfy@gmail.com',
              to: user.email,
              subject: subject,
              html: personalizedContent,
          };
      });

      await Promise.all(emailsToSend.map((email) => transporterSec.sendMail(email)));

      res.status(200).json({ message: 'Emails sent successfully!' });
  } catch (error) {
      console.error('Error sending emails:', error);
      res.status(500).json({ message: 'Error sending emails', error });
  }
});

app.get('/get-users/all/admin', async (req, res) => {
  try {
      const users = await query('SELECT email, unique_id FROM users', []);
      res.status(200).json({ users });
  } catch (error) {
      console.error('Error fetching users:', error);
      res.status(500).json({ message: 'Error fetching users', error });
  }
});


// Endpoint to log download requests
app.post('/api/log-download', (req, res) => {
  console.log('Download requested:', req.body);
  res.status(200).send({ message: 'Download request logged' });
});

// Get updates
app.get('/api/updates/get', (req, res) => {
  connection.query('SELECT * FROM updates ORDER BY created_at DESC', (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      res.json(results);
  });
});

// Post a new update
app.post('/api/updates/add', (req, res) => {
  const { title, content } = req.body;
  connection.query('INSERT INTO updates (title, content) VALUES (?, ?)', [title, content], (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      res.status(201).json({ id: results.insertId, title, content });
  });
});

// Set the file size limit for AI image processing (e.g., 100MB)
const AI_MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// Create a new multer instance for AI image processing
const uploadAI = multer({
  limits: {
    fileSize: AI_MAX_FILE_SIZE, // Set the max file size limit for AI processing
  },
  // Store files in memory (alternatively, you can use disk storage if needed)
  storage: multer.memoryStorage(),
  // Optionally, add a file filter if required
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported image format'), false);
    }
  },
});

// Your image processing logic
const processImage = (file) => {
  return new Promise((resolve, reject) => {
    try {
      // Convert buffer to Base64
      const base64Image = file.buffer.toString('base64');
      resolve(base64Image);
    } catch (error) {
      reject(error);
    }
  });
};


app.post('/api/process-images', uploadAI.single('image'), async (req, res) => {
  try {
    const { prompt, token } = req.body;

    // Validate token
    if (!token) {
      return res.status(400).json({ error: 'Token is required.' });
    }

    // Get user ID from token
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not authenticated.' });
    }

    if (!req.file && !prompt) {
      return res.status(400).json({ error: 'Either image or prompt must be provided.' });
    }

    let imageBase64 = null;

    if (req.file) {
      console.log('Received image, processing...');
      imageBase64 = await processImage(req.file); // Convert image to Base64
    } else {
      console.log('No image received.');
    }

    console.log('Received prompt:', prompt || 'No prompt provided.');

    // Send image and prompt to AI model
    const response = await model.generateContent([
      { inlineData: { data: imageBase64, mimeType: req.file.mimetype } },
      prompt || '', // Use prompt if available
    ]);

    console.log('AI responded.');

    const resultText = response?.response?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!resultText) {
      throw new Error('No AI response text received.');
    }

    // Store user input and AI response in the database
    await query(
      'INSERT INTO ai_history (user_id, user_message, ai_response) VALUES (?, ?, ?)',
      [userId, prompt || 'Image uploaded by user', resultText]
    );

    // Send the response back
    res.json({ result: resultText });
  } catch (error) {
    console.error('Error during image processing:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post("/ai-chatbox/pdf/ai", uploadPDF.single("file"), async (req, res) => {
  try {
    const { prompt, token } = req.body; // Extract user prompt and token
    const file = req.file; // Extract the uploaded file (if any)

    // Validate that either a prompt or a file is provided
    if (!prompt && !file) {
      return res.status(400).json({ error: "No input provided (message or file)" });
    }

    // Validate the user's token and extract the user ID
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    let resultText = "";

    // Handle PDF file processing
    if (file) {
      const filePath = file.path; // Path to the uploaded file

     

      // Load the generative model
      const model = genAI.getGenerativeModel({ model: "models/gemini-1.5-flash" });
      const result = await model.generateContent([
        {
          inlineData: {
            data: Buffer.from(fs.readFileSync(filePath)).toString("base64"),
            mimeType: "application/pdf",
          },
        },
        prompt,
      ]);

      // Extract the result content
      resultText = result.response.candidates?.[0]?.content?.parts?.[0]?.text || "No content generated";

      // Clean up temporary files
      fs.unlinkSync(filePath);
    } else {
      // Handle text prompt without file
      const model = genAI.getGenerativeModel({ model: "models/gemini-1.5-chat" });
      const result = await model.generateContent([{ inlineData: { data: prompt } }]);

      resultText = result.response.candidates?.[0]?.content || "No content generated";
    }

    // Save the user input and AI response to the database
    const queryStr = `
      INSERT INTO ai_history (user_id, user_message, ai_response)
      VALUES (?, ?, ?)
    `;
    await query(queryStr, [userId, prompt || "PDF uploaded by user", resultText]);

    // Respond with the AI result
    res.json({ result: resultText, message: "AI response generated successfully!" });
    console.log("AI response from pdf.");
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});


app.post("/summarize-pdf/notes", uploadPDF.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const filePath = req.file.path;
    const options = JSON.parse(req.body.options); // Parse selected options
    const token = req.body.token; // Extract token from the request body

    // Extract user_id from token
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Check premium status
    const isPremium = req.body.isPremium; // Pass premium status from frontend

    // If user is not premium, check if they have already created more than 5 flashcards today
    if (!isPremium) {
      const today = new Date().toISOString().split("T")[0]; // Get today's date in YYYY-MM-DD format

      const queryStr = `SELECT COUNT(*) AS flashcardsCount FROM flashcards WHERE user_id = ? AND DATE(created_at) = ?`;
      const result = await query(queryStr, [userId, today]);

      const flashcardsCount = result[0]?.flashcardsCount || 0;
      if (flashcardsCount >= 5) {
        return res.status(403).json({ error: "You can only create up to 5 flashcards per day as a free user." });
      }
    }

    // Build AI prompt based on selected options, ensuring plain HTML output without extra text
    const prompts = {
      summary: `You are an AI responsible for generating concise notes from documents. Your task is to summarize this document and respond ONLY in valid plain HTML. Use tags such as <h1> for the title, <h2> for headings, and <p> for paragraphs. DO NOT include any introductory text like "Here is the summary" or "This is in HTML format." DO NOT use markdown or non-HTML elements. Your output must STRICTLY be the requested summary in raw HTML format. Any extraneous content will invalidate the response.`,
      key_points: `You are an AI designed to extract key points from documents. Your task is to extract the main points and respond ONLY in valid plain HTML using <ul> and <li> tags. DO NOT include any additional text like "Here are the key points" or "This is in HTML." DO NOT use markdown or non-HTML content. Your response must STRICTLY contain the key points formatted in raw HTML. Deviation from this format will invalidate the output.`,
      detailed_explanation: `You are an AI responsible for generating detailed explanations of documents. Your task is to provide a detailed explanation of this document and respond ONLY in valid plain HTML. Use <h1> for the title, <h2> for subheadings, and <p> for detailed paragraphs. DO NOT include any additional text like "Here is the explanation" or any markdown formatting. Respond STRICTLY with valid raw HTML content. Any additional or non-compliant content will render the response invalid.`,
      question_generation: `You are an AI designed to generate questions from documents. Your task is to create questions and answers and respond ONLY in valid plain HTML. Use <p> for each question and <ul> with <li> for the answer options. DO NOT include any introductory phrases such as "Here are the questions" or "In HTML format." Respond STRICTLY with valid raw HTML content. Any extra or non-HTML content will invalidate your response.`,
    };

    const userPrompt = options.map((opt) => prompts[opt]).join("\n");

    const model = genAI.getGenerativeModel({ model: "models/gemini-1.5-flash" });

    let generatedText;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const result = await model.generateContent([
          {
            inlineData: {
              data: Buffer.from(fs.readFileSync(filePath)).toString("base64"),
              mimeType: "application/pdf",
            },
          },
          userPrompt,
        ]);

        // Extract generated content (HTML)
        generatedText = result.response.candidates?.[0]?.content?.parts?.[0]?.text || "No content generated";

        console.log(`AI successfully processed the document on attempt ${attempt}`);
        break; // Exit loop if successful
      } catch (error) {
        console.error(`Attempt ${attempt} failed:`, error.message);

        if (attempt === MAX_RETRIES) {
          throw new Error("AI service failed after multiple attempts.");
        }

        // Exponential backoff delay (2^attempt * 100 ms)
        const delayMs = Math.pow(2, attempt) * 100;
        console.log(`Retrying in ${delayMs}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }

    // Insert notes into the database
    const queryStrInsert = `
    INSERT INTO flashcards (title, description, headings, is_public, user_id, subject_id, is_pdf)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    const title = "Generated Notes"; // Example title
    const description = "Notes generated from uploaded PDF"; // Example description
    const isPublic = false; // Notes are private by default
    const subjectId = null; // No subject_id for now
    const isPdf = 1; // Setting the is_pdf column to 1

    const resultInsert = await query(queryStrInsert, [title, description, generatedText, isPublic, userId, subjectId, isPdf]);

    // Retrieve the inserted note ID
    const noteId = resultInsert.insertId;

    // Cleanup temporary file
    fs.unlinkSync(filePath);

    res.json({ result: generatedText, message: "Notes saved successfully!", noteId });
    console.log("Created notes from PDF");
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});

// API endpoint to fetch the number of flashcards created from PDFs
app.get("/api/flashcards/count/pdf-premium", async (req, res) => {
  try {
    const token = req.headers.authorization; // Extract token from the Authorization header
    
    if (!token) {
      return res.status(400).json({ error: "Token is required" });
    }

    // Extract user_id from token
    const userId = await getUserIdFromToken(token);

    // Get the count of flashcards created from PDFs by the user
    const queryStr = `
      SELECT COUNT(*) AS flashcardsCount
      FROM flashcards
      WHERE user_id = ? AND is_pdf = 1 AND DATE(created_at) = CURDATE()
    `;

    connection.query(queryStr, [userId], (err, result) => {
      if (err) {
        console.error("Error fetching flashcards count:", err);
        return res.status(500).json({ error: "Something went wrong!" });
      }
      const flashcardsCount = result[0].flashcardsCount;
      res.json({ flashcardsCount });
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});

app.post('/api/notes/generate', async (req, res) => {
  const { topic, types, token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not found' });
    }

    // Get today's date in YYYY-MM-DD format
    const todayDate = new Date().toISOString().split('T')[0];

    // Initialize the prompt with basic structure
    let prompt = `Generate notes on the topic "${topic}". Format the notes in HTML using only <p>, <li>, <ul>, <h1>, <h2>, and <h3> tags. The notes should be detailed, structured, and easy to read.`;

    // Handle specific types of notes requested by the user
    Object.keys(types).forEach(type => {
      if (types[type]) { // Check if the type is true
        if (type === 'summary') {
          prompt += ' Provide a brief summary of the topic.';
        } else if (type === 'detailed') {
          prompt += ' Provide a detailed explanation of the topic, including key concepts and important details.';
        } else if (type === 'question-and-answer') {
          prompt += ' Include potential questions and answers related to the topic.';
        } else if (type === 'key points') {
          prompt += ' Include key points that summarize the most important aspects of the topic.';
        } else if (type === 'subtopics') {
          prompt += ' Break down the topic into relevant subtopics with explanations.';
        } else if (type === 'important questions') {
          prompt += ' Provide a list of important questions related to the topic that may be asked during exams or discussions.';
        }
      }
    });

    console.log('Generating notes with prompt:', prompt);

    // Function to attempt generating notes and retry on failure
    const generateNotesWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          // Call the AI model with the prompt
          const chat = model.startChat({
            history: [
              { role: 'user', parts: [{ text: 'Hello' }] },
              { role: 'model', parts: [{ text: 'I can help generate notes on your topic!' }] },
            ],
          });

          const result = await chat.sendMessage(prompt);

          // Extract only the HTML part from the AI response
          const responseText = result.response.text();
          const htmlResponse = responseText.match(/<p[\s\S]*?<\/p>/g);
          if (!htmlResponse || htmlResponse.length === 0) {
            throw new Error('Could not extract valid HTML from AI response');
          }

          // Join the extracted HTML notes
          const notesContent = htmlResponse.join(' ');

          return notesContent; // Return the successfully generated notes content
        } catch (error) {
          attempts++;
          console.log(`Attempt ${attempts} failed, retrying...`);

          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate notes after multiple attempts');
          }

          // Delay before retrying
          await delay(2000); // Delay for 2 seconds before the next attempt
        }
      }
    };

    // Try to generate notes with retries
    const notesContent = await generateNotesWithRetry();

    const notesData = {
      userId,
      title: topic || 'Untitled Notes',
      description: `Notes on the topic: ${topic}`,
      headings: notesContent, // HTML content as headings
      is_public: false,
      subject_id: null, // You can add subject id if required
      is_ai: 1, // Set the new column is_ai to 1 for AI-generated notes
    };
    
    // Insert notes into the database and get the id using the promisified query
    const result = await query('INSERT INTO flashcards (title, description, headings, is_public, user_id, subject_id, is_ai) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      notesData.title,
      notesData.description,
      notesData.headings,
      notesData.is_public,
      notesData.userId,
      notesData.subject_id,
      notesData.is_ai, // Inserting the AI flag
    ]);
    
    // Assuming the query returns the inserted row with an 'id' field
    const noteId = result.insertId; // This depends on your query and database setup
    
    // Add the id to notesData and send it back in the response
    res.json({ notes: { ...notesData, id: noteId } });

  } catch (error) {
    console.error('Error generating notes:', error);
    res.status(500).json({ error: error.message });
  }
});


// **Elite Notes Generation API**
app.post('/api/notes/generate/elite/premium', async (req, res) => {
  const { topic, token } = req.body;

  try {
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not found' });
    }

    // **Dynamic AI prompt including the topic**
    const prompt = `
   You are an advanced AI designed to generate **elite-level study notes** exclusively for Edusify users.  
Your goal is to create **highly detailed, structured, and well-formatted notes** to help students excel in **exams, revisions, and in-depth learning**.  

## **Instructions for Generating Notes on: "${topic}"**  

### **1. Content Depth & Clarity**  
- The notes should be **highly detailed**, covering all key concepts of "${topic}" with **deep insights and clear explanations**.  
- Break down **complex ideas step by step**, making them easy to grasp.  
- Include **real-world applications** and at least **three practical examples** to enhance understanding.  
- Use **accurate definitions** and well-explained terms.  

### **2. Structured Formatting for Maximum Readability**  
Use **proper HTML structure** to ensure visually appealing and organized notes:  
- **Main Topic** → Use a large heading.  
- **Subtopics & Key Concepts** → Use subheadings for better clarity.  
- **Detailed Explanations** → Write in paragraph form for in-depth understanding.  
- **Key Takeaways & Important Points** → Highlight with bullet points.  
- **Bold** important terms and **italicize** key emphasis points.  
- **Blockquotes** → Use for significant insights, key definitions, or expert explanations.  
- **Code Blocks** → Include for mathematical, scientific, or programming-related topics.  

### **3. Enhancements to Improve Learning**  

✅ **Key Takeaways & Summaries**  
- At the end of **every major section**, provide a summary of the most important points.  
- Ensure summaries are concise and focus on **exam-relevant information**.  

✅ **Common Mistakes & Misconceptions**  
- Highlight **frequent student errors** related to "${topic}".  
- Provide **corrections and explanations** to help students avoid mistakes.  

✅ **Formulas & Diagrams** *(if applicable)*  
- Include **all essential formulas** related to "${topic}".  
- Explain **how these formulas are derived and used** in problem-solving.  

✅ **Exam-Oriented Practice Questions**  
- Provide at least **5 potential exam questions** for "${topic}".  
- Where applicable, include **step-by-step solutions**.  

✅ **Memory Aids & Mnemonics**  
- Offer **study hacks, acronyms, or mnemonics** to improve retention.  

✅ **Connections to Other Topics**  
- Explain how "${topic}" is related to **other subjects or real-world applications**.  

### **4. Final Goal**  
The notes should:  
✔️ Be **comprehensive, structured, and exam-focused**.  
✔️ **Not be short or superficial**—ensure deep coverage.  
✔️ Deliver a **premium, exclusive, and high-end study experience** for Edusify users.  

Ensure the notes **look premium, feel exclusive, and provide everything needed to master "${topic}"**.

    `;

    console.log('Generating elite notes on:', topic);

    // Function to attempt generating notes and retry on failure
    const generateNotesWithRetry = async () => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          // Call the AI model with the prompt
          const chat = model.startChat({
            history: [
              { role: 'user', parts: [{ text: 'Hello' }] },
              { role: 'model', parts: [{ text: 'I can help generate notes on your topic!' }] },
            ],
          });

          const result = await chat.sendMessage(prompt);

          // Extract only the HTML part from the AI response
          const responseText = result.response.text();
          const htmlResponse = responseText.match(/<p[\s\S]*?<\/p>/g);
          if (!htmlResponse || htmlResponse.length === 0) {
            throw new Error('Could not extract valid HTML from AI response');
          }

          // Join the extracted HTML notes
          const notesContent = htmlResponse.join(' ');

          return notesContent; // Return the successfully generated notes content
        } catch (error) {
          attempts++;
          console.log(`Attempt ${attempts} failed, retrying...`);

          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate notes after multiple attempts');
          }

          // Delay before retrying
          await delay(2000); // Delay for 2 seconds before the next attempt
        }
      }
    };

    // Try to generate notes with retries
    const notesContent = await generateNotesWithRetry();

    // **Save generated notes to the database**
    const result = await query(
      `INSERT INTO flashcards (user_id, title, description, headings, is_ai) VALUES (?, ?, ?, ?, ?)`,
      [userId, topic, `Notes on ${topic}`, notesContent, 1]
    );

    const noteId = result.insertId;

    res.json({
      message: 'Notes generated successfully!',
      notes: { id: noteId, title: topic, content: notesContent },
    });

  } catch (error) {
    console.error('Error generating notes:', error);
    res.status(500).json({ error: error.message });
  }
});

// API endpoint to fetch the number of flashcards created from AI
app.get("/api/flashcards/count/ai-premium", async (req, res) => {
  try {
    const token = req.headers.authorization; // Extract token from the Authorization header
    
    if (!token) {
      return res.status(400).json({ error: "Token is required" });
    }

    // Extract user_id from token
    const userId = await getUserIdFromToken(token);

    // Get the count of flashcards created from PDFs by the user
    const queryStr = `
      SELECT COUNT(*) AS flashcardsCount
      FROM flashcards
      WHERE user_id = ? AND is_ai = 1 AND DATE(created_at) = CURDATE()
    `;

    connection.query(queryStr, [userId], (err, result) => {
      if (err) {
        console.error("Error fetching flashcards count:", err);
        return res.status(500).json({ error: "Something went wrong!" });
      }
      const flashcardsCount = result[0].flashcardsCount;
      res.json({ flashcardsCount });
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});

app.post("/api/saveGoal", async (req, res) => {
  const { token, data } = req.body;



  try {
    const userId = await getUserIdFromToken(token);

    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Parse the subjects field to ensure it's an array
    const subjects = JSON.parse(data.subjects); // Parse the string into an array

    const sql = `
    INSERT INTO user_goal (
      user_id,
      grade,
      goal,
      study_time,
      speed,
      revision_method,
      pomodoro_preference,
      subjects,
      recent_grades,        -- Add this
      exam_details,         -- Add this
      daily_routine         -- Add this
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  const params = [
    userId,
    data.grade,
    data.goal,
    data.study_time,
    data.speed,
    data.revision_method,
    data.pomodoro_preference,
    JSON.stringify(subjects),
    JSON.stringify(data.recent_grades),  // Convert recent grades to JSON if needed
    JSON.stringify(data.exam_details),   // Convert exam details to JSON if needed
    JSON.stringify(data.daily_routine)   // Convert daily routine to JSON if needed
  ];
  


    await query(sql, params);

    const prompt = `
     Generate a personalized study plan based on the following data:
  - Goal: ${data.goal}
  - Daily Study Time: ${data.study_time}
  - Subjects: ${subjects.map((sub) => sub.subject).join(", ")}
  - Pomodoro Preference: ${data.pomodoro_preference ? "Yes" : "No"}
  - Speed: ${data.speed}
  - Recent Grades: ${JSON.stringify(data.recent_grades)}
  - Exam Details: ${JSON.stringify(data.exam_details)}
  - Daily Routine: ${JSON.stringify(data.daily_routine)}
    
    The study plan should adhere to the following JSON structure:
    
    {
      "study_plan": {
        "goal": "Goal description",
        "notes": "This plan is a suggestion and can be adjusted to suit your needs. Remember to take breaks and maintain a healthy study-life balance.",
        "speed": "fast",  // or "medium" or "slow"
        "subjects": ["List of subjects to study"],
        "daily_study_time": "X hours",  // e.g., "1-2 hours"
        "weekly_timetable": [
          {
            "day": "Monday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          },
          {
            "day": "Tuesday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          },
          {
            "day": "Wednesday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          },
          {
            "day": "Thursday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          },
          {
            "day": "Friday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          },
          {
            "day": "Saturday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          },
          {
            "day": "Sunday",
            "tips": "Study tips for this day",
            "method": "Study method (e.g., Pomodoro)",
            "subjects": ["Subject 1", "Subject 2", ...],
            "hours_allocation": [
              {
                "hours": "X",  // Number of hours allocated for the subject
                "subject": "Subject Name"
              },
              // More subjects can be added here
            ],
            "total_study_time": X,  // Total study time for that day in hours
            "current_situation": X,  // Current situation out of 10
            "AI_task_generation_instructions": "Specific task generation instructions for this day"
          }
        ],
        "pomodoro_preference": true  // Or false
      }
    }
    
    Ensure the JSON format is consistent and contains all the fields as described. The subjects should be based on the provided data, and the study plan should be balanced based on the available study time each day. Be sure to include relevant study tips and task generation instructions for each day.
    
    Provide the study plan as a valid JSON object.
    `;
    
    
    

    console.log("Generating study plan with AI");

    // AI Integration Logic
    const generateStudyPlanWithRetry = async () => {
      let attempts = 0;
      const MAX_RETRIES = 10;

      while (attempts < MAX_RETRIES) {
        try {
          const chat = model.startChat({ history: [] });
          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, "").trim();
          let studyPlan;

          try {
            studyPlan = JSON.parse(sanitizedResponse);
          } catch (parseError) {
            throw new Error("Invalid JSON response from the AI model");
          }

          return studyPlan;
        } catch (error) {
          attempts++;
          if (attempts === MAX_RETRIES) {
            throw new Error("Failed to generate study plan after multiple attempts");
          }
          await new Promise((resolve) => setTimeout(resolve, 2000)); // Retry delay
        }
      }
    };

    // Get the study plan by calling the retry function
    const studyPlan = await generateStudyPlanWithRetry();

    // Insert the study plan into the database
    const studyPlanQuery = "INSERT INTO study_plans (user_id, study_plan) VALUES (?, ?)";
    connection.query(studyPlanQuery, [userId, JSON.stringify(studyPlan)], (err, results) => {
      if (err) {
        console.error("Error inserting study plan:", err);
        return res.status(500).json({ success: false, message: "Error saving study plan" });
      }
      console.log("ai plan generated!", userId)
      // Respond with the generated study plan
      res.json({
        success: true,
        message: "Goal and study plan saved successfully!",
        studyPlan: studyPlan
      });
    });
  } catch (error) {
    console.error("Error saving goal and generating study plan:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});


app.post("/api/study-plan", async (req, res) => {
  try {
    const { token } = req.body; // Get token from the request body

    if (!token) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    // Get userId from token (this function should be defined based on your auth system)
    const userId = await getUserIdFromToken(token);

    // Query to get the latest study plan from the database
    const sql = `
      SELECT study_plan 
      FROM study_plans 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 1
    `;

    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Study plan not found" });
    }

    let studyPlan = results[0].study_plan;

    // Check if the study plan is already an object and doesn't need parsing
    if (typeof studyPlan === 'string') {
      studyPlan = JSON.parse(studyPlan); // Parse it only if it's a string
    }

    // Send the parsed study plan as the response
    res.status(200).json({ success: true, data: studyPlan });
  } catch (error) {
    console.error("Error fetching study plan:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.post("/api/update-study-plan", async (req, res) => {
  try {
    const { token, studyPlan } = req.body; // Get token and updated study plan from the request body

    if (!token || !studyPlan) {
      return res.status(400).json({ success: false, message: "Token and study plan are required" });
    }

    // Get userId from token (this function should be defined based on your auth system)
    const userId = await getUserIdFromToken(token);

    // Convert the study plan to a string (if it's an object) for database storage
    const studyPlanString = typeof studyPlan === 'object' ? JSON.stringify(studyPlan) : studyPlan;

    // SQL query to update the study plan
    const sql = `
      UPDATE study_plans
      SET study_plan = ?
      WHERE user_id = ?
    `;

    const results = await query(sql, [studyPlanString, userId]);

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Study plan not found or update failed" });
    }

    // Respond with success
    res.status(200).json({ success: true, message: "Study plan updated successfully" });
  } catch (error) {
    console.error("Error updating study plan:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});


app.post("/api/study-plan-created-date", async (req, res) => {
  try {
    const { token } = req.body; // Get token from the request body

    if (!token) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    // Get userId from token (this function should be defined based on your auth system)
    const userId = await getUserIdFromToken(token);

    // Query to get the latest study plan from the database
    const sql = `
      SELECT created_at 
      FROM study_plans 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 1
    `;

    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Study plan not found" });
    }

    const created_at = results[0].created_at;

    // Send the created_at date as the response
    res.status(200).json({ success: true, data: { created_at } });
  } catch (error) {
    console.error("Error fetching study plan:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});



app.post('/api/today-pomodoro-study-plan', async (req, res) => {
  const token = req.body.token;

  try {
    const userId = await getUserIdFromToken(token);

    if (!userId) {
      console.log('Unauthorized: No user ID found in token');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const todayDate = moment().format('YYYY-MM-DD'); // Only date

    const sql = `
      SELECT SUM(duration) AS totalDuration FROM pomodoro_date
      WHERE user_id = ? AND DATE(end_time) = ?
    `;

    const results = await query(sql, [userId, todayDate]);

    if (!results[0].totalDuration) {
      return res.status(404).json({ message: 'No Pomodoro data for today' });
    }

    const totalDurationInSeconds = results[0].totalDuration;
    res.json({ durationInSeconds: totalDurationInSeconds });


  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Server Error', message: err.message });
  }
});


app.post("/api/study-plan/dashboard", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(401).json({ success: false, message: "No token provided" });
    }

    const userId = await getUserIdFromToken(token);

    const sql = `
      SELECT study_plan 
      FROM study_plans 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 1
    `;

    const results = await query(sql, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Study plan not found" });
    }

    let studyPlan = results[0].study_plan;

    if (typeof studyPlan === 'string') {
      studyPlan = JSON.parse(studyPlan); 
    }

    res.status(200).json({ success: true, data: studyPlan });
  } catch (error) {
    console.error("Error fetching study plan:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});


// Route to fetch tasks and calculate completion percentages
app.post('/getTasks/plan/study', async (req, res) => {
  const token = req.body.token; // Assuming token is passed for user identification (e.g., JWT)

  try {
    const userId = await getUserIdFromToken(token); // Get user ID from token

    // Get today's date in the format YYYY-MM-DD
    const today = new Date().toISOString().split('T')[0];

    // Fetch tasks for today and overall
    const todayTasks = await query(
      `SELECT * FROM tasks WHERE user_id = ? AND (due_date = ? OR completed_at IS NOT NULL)`,
      [userId, today]
    );

    const allTasks = await query('SELECT * FROM tasks WHERE user_id = ?', [userId]);

    // Calculate task completion percentages
    const completedTasksToday = todayTasks.filter(task => task.completed === 1).length;
    const totalTasksToday = todayTasks.length;
    const completedTasksOverall = allTasks.filter(task => task.completed === 1).length;
    const totalTasksOverall = allTasks.length;

    const taskCompletionTodayPercentage = totalTasksToday > 0 ? (completedTasksToday / totalTasksToday) * 100 : 0;
    const taskCompletionOverallPercentage = totalTasksOverall > 0 ? (completedTasksOverall / totalTasksOverall) * 100 : 0;

    res.json({
      today: todayTasks,
      all: allTasks,
      taskCompletionTodayPercentage,
      taskCompletionOverallPercentage,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred while fetching tasks' });
  }
});



// Razorpay setup
const razorpay = new Razorpay({
  key_id: 'rzp_live_jPX6SxetQbApHC',
  key_secret: 'ec9nrw9RjbIcvpkufzaYxmr6',
});

app.post('/buy-premium', async (req, res) => {
  try {
    const { amount, currency, subscription_plan, token, duration } = req.body;
    
    // Extract user ID from token
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const options = {
      amount: amount * 100, // Convert to paise
      currency,
      receipt: `order_rcptid_${Math.floor(Math.random() * 100000)}`,
      notes: { subscription_plan, userId, duration },
    };

    razorpay.orders.create(options, (err, order) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ order });
    });

  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/verify-payment', async (req, res) => {
  try {
    const { payment_id, order_id, signature, token, subscription_plan, duration } = req.body;

    // Extract user ID from token
    const userId = await getUserIdFromToken(token);
    if (!userId) {
      console.error('Invalid or expired token');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const body = `${order_id}|${payment_id}`;
    const expected_signature = crypto
      .createHmac('sha256', 'ec9nrw9RjbIcvpkufzaYxmr6') // Use your secret key
      .update(body)
      .digest('hex');

    if (expected_signature === signature) {
      // Calculate expiry date based on duration
      const expiryDate = new Date();
      if (duration === 'weekly') expiryDate.setDate(expiryDate.getDate() + 7);
      else if (duration === 'monthly') expiryDate.setDate(expiryDate.getDate() + 30);
      else if (duration === '6months') expiryDate.setDate(expiryDate.getDate() + 180);

      const queryText = `
        INSERT INTO subscriptions (user_id, subscription_plan, payment_status, payment_date, expiry_date)
        VALUES (?, ?, ?, NOW(), ?)
      `;

      console.log(`User ${userId} upgraded to premium for ${duration}.`);

      try {
        await query(queryText, [userId, subscription_plan, 'success', expiryDate]);
        res.json({ success: true });
      } catch (dbError) {
        console.error('Database error:', dbError);
        res.status(500).json({ error: 'Database error' });
      }
    } else {
      console.error('Signature mismatch');
      res.status(400).json({ success: false });
    }
  } catch (error) {
    console.error('Error in verify-payment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Function to generate a unique gift card code
const generateGiftCardCode = () => {
  return 'EDU-' + crypto.randomBytes(4).toString('hex').toUpperCase();
};

// Buy Gift Card
app.post('/buy-gift-card', async (req, res) => {
  try {
    const { amount, currency, token } = req.body;
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const options = {
      amount: amount * 100, // Convert to paise
      currency,
      receipt: `giftcard_${Math.floor(Math.random() * 100000)}`,
      notes: { userId },
    };

    razorpay.orders.create(options, async (err, order) => {
      if (err) return res.status(500).json({ error: err });

      const giftCardCode = generateGiftCardCode();

      const queryText = `
        INSERT INTO gift_cards (user_id, code, amount, status, created_at)
        VALUES (?, ?, ?, 'unused', NOW())
      `;
      await query(queryText, [userId, giftCardCode, amount]);

      res.json({ order, giftCardCode });
    });

  } catch (error) {
    console.error('Error in buy-gift-card:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify Payment for Gift Card
app.post('/verify-gift-card-payment', async (req, res) => {
  try {
    const { payment_id, order_id, signature, token, giftCardCode } = req.body;
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const body = `${order_id}|${payment_id}`;
    const expected_signature = crypto
      .createHmac('sha256', 'ec9nrw9RjbIcvpkufzaYxmr6')
      .update(body)
      .digest('hex');

    if (expected_signature === signature) {
      await query('UPDATE gift_cards SET status = "valid" WHERE code = ?', [giftCardCode]);
      res.json({ success: true, message: 'Gift card activated successfully' });
    } else {
      res.status(400).json({ success: false, message: 'Signature mismatch' });
    }
  } catch (error) {
    console.error('Error in verify-gift-card-payment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/redeem-gift-card', async (req, res) => {
  try {
    const { giftCardCode, token } = req.body;

    // Extract user ID from token
    const userId = await getUserIdFromToken(token);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    // Check if the gift card exists and is valid
    const giftCard = await query('SELECT * FROM gift_cards WHERE code = ? AND status = "valid"', [giftCardCode]);

    if (giftCard.length === 0) {
      return res.status(400).json({ error: 'Invalid or already redeemed gift card' });
    }

    const amount = giftCard[0].amount;

    // Determine subscription duration based on gift card amount
    let duration;
    if (amount === 39) duration = 'weekly';
    else if (amount === 99) duration = 'monthly';
    else if (amount === 499) duration = '6months';
    else return res.status(400).json({ error: 'Invalid gift card amount' });

    // Calculate expiry date
    const expiryDate = new Date();
    if (duration === 'weekly') expiryDate.setDate(expiryDate.getDate() + 7);
    else if (duration === 'monthly') expiryDate.setDate(expiryDate.getDate() + 30);
    else if (duration === '6months') expiryDate.setDate(expiryDate.getDate() + 180);

    // Mark the gift card as used
    await query('UPDATE gift_cards SET status = "used", redeemed_by = ?, redeemed_at = NOW() WHERE code = ?', [userId, giftCardCode]);

    // Add premium subscription
    const queryText = `
      INSERT INTO subscriptions (user_id, subscription_plan, payment_status, payment_date, expiry_date)
      VALUES (?, ?, ?, NOW(), ?)
    `;
    await query(queryText, [userId, duration, 'success', expiryDate]);

    res.json({ success: true, message: `Gift card redeemed! Premium activated for ${duration}.` });
  } catch (error) {
    console.error('Error in redeem-gift-card:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Get all gift cards for the logged-in user
app.get('/get-gift-cards', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from "Bearer token"
    const userId = await getUserIdFromToken(token);
    
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorized' });

    const query = `
      SELECT code, amount, status
      FROM gift_cards 
      WHERE user_id = ? 
    `;

    connection.query(query, [userId], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      res.json({ success: true, giftCards: results });
    });

  } catch (error) {
    console.error('Error fetching gift cards:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/get-friends-gift', async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const userId = await getUserIdFromToken(token);

    const friendsQuery = `
      SELECT DISTINCT u.id, u.unique_id FROM users u
      JOIN friends f ON (f.user_id_1 = u.id OR f.user_id_2 = u.id)
      WHERE (f.user_id_1 = ? OR f.user_id_2 = ?) AND u.id != ?
    `;
    const friends = await query(friendsQuery, [userId, userId, userId]);

    res.json({ friends });
  } catch (error) {
    console.error('Error fetching friends:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


app.post('/gift-gift-card', async (req, res) => {
  try {
    const { token, friendId, giftCardCode } = req.body;
    const userId = await getUserIdFromToken(token);

    // Check if the friend already has premium
    const existingSubscription = await query(
      'SELECT user_id FROM subscriptions WHERE user_id = ? AND expiry_date > NOW()',
      [friendId]
    );

    if (existingSubscription.length > 0) {
      return res.status(400).json({ message: 'This user already has an active premium subscription.' });
    }

    // Check if the gift card is valid
    const validGiftCard = await query(
      'SELECT code FROM gift_cards WHERE code = ? AND status = "valid"',
      [giftCardCode]
    );

    if (validGiftCard.length === 0) {
      return res.status(400).json({ message: 'Invalid or already used gift card.' });
    }

    // Mark gift card as used
    await query(
      'UPDATE gift_cards SET status = "used", redeemed_by = ?, redeemed_at = NOW() WHERE code = ?',
      [friendId, giftCardCode]
    );

    // Add subscription
    const expiryDate = new Date();
    expiryDate.setMonth(expiryDate.getMonth() + 1); // 1-month premium

    await query(
      'INSERT INTO subscriptions (user_id, subscription_plan, payment_status, payment_date, expiry_date) VALUES (?, ?, ?, NOW(), ?)',
      [friendId, '1 Month Premium', 'gifted', expiryDate]
    );

    res.json({ message: 'Gift card successfully gifted!' });
  } catch (error) {
    console.error('Error gifting card:', error);
    res.status(500).json({ message: 'Failed to gift card.' });
  }
});


// API endpoint to check if the user is premium
app.post('/check-premium', async (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(400).json({ message: 'Token is required' });
  }

  try {
    const userId = await getUserIdFromToken(token);

    // Check in subscriptions table if user exists and is premium
    connection.query('SELECT * FROM subscriptions WHERE user_id = ?', [userId], (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Database error', error: err });
      }

      if (results.length === 0) {
        return res.status(200).json({ premium: false });
      }

      const subscription = results[0];

      // Check expiry date
      const currentDate = new Date();
      const expiryDate = new Date(subscription.expiry_date);

      if (expiryDate < currentDate) {
        return res.status(200).json({ premium: false });
      }

      return res.status(200).json({ premium: true });
    });
  } catch (error) {
    return res.status(500).json({ message: 'Error processing token', error });
  }
});

app.post('/api/magic/usage', async (req, res) => {
  const { token } = req.body;

  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);

    if (!userId) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Step 2: Check user's magic usage count for the past 7 days
    const [usageResult] = await connection.promise().query(
      'SELECT COUNT(*) AS usage_count FROM magic_usage WHERE user_id = ? AND created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)',
      [userId]
    );

    const usageCount = usageResult[0].usage_count;
    const maxFreeMagicUsage = 2; // Max allowed Magic usage per week for free users

    // Step 3: Determine if the user can use Magic based on weekly limit
    const canUseMagic = usageCount < maxFreeMagicUsage;

    // Step 4: Return the result
    res.json({ canUseMagic });
  } catch (error) {
    console.error('Error checking magic usage:', error);
    res.status(500).json({ error: 'Error checking magic usage' });
  }
});



app.post('/api/pomodoro/ai-recommendation', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const userId = await getUserIdFromToken(token); // Fetch user ID from token

    // Fetch user's past Pomodoro sessions (including null durations)
    const query = `
      SELECT session_type, duration, session_date 
      FROM pomodoro_date 
      WHERE user_id = ?
    `;

    connection.query(query, [userId], async (err, results) => {
      if (err) {
        console.error('Database error (fetching pomodoro data):', err);
        return res.status(500).json({ error: 'Failed to fetch pomodoro data' });
      }

      // Get today's day (e.g., Monday, Tuesday)
      const today = moment().format('dddd');

      // Format session data for AI prompt
      const sessionData = results.map(row => ({
        type: row.session_type || "unknown",  // Handle null session type
        duration: row.duration ? row.duration / 60 : null, // Convert to minutes (keep null if duration is missing)
        date: row.session_date,
        day: moment(row.session_date).format('dddd') // Extract day name from date
      }));

      // AI Prompt
      const prompt = `Analyze the following Pomodoro session history and suggest an optimal study and break duration for today (${today}):
      
      Sessions Data: 
      ${JSON.stringify(sessionData, null, 2)}

      Guidelines:
      1. Suggest a balanced study and break time based on past completed sessions.
      2. If user studies longer on weekends (Saturday/Sunday), suggest longer study times for those days.
      3. If the user struggles with long sessions on weekdays, suggest shorter intervals for days like Monday-Friday.
      4. Ignore sessions with null durations but consider them for behavioral patterns.
      5. The break should be proportionate to study time (not too long or too short).
      6. Return only a JSON object like this:
      
      {
        "studyTime": "number (in minutes)",
        "breakTime": "number (in minutes)"
      }
      `;

      console.log('Generating AI-based Pomodoro recommendations for', today, userId);

      // AI Integration & Retry Logic
      const generateRecommendationsWithRetry = async () => {
        let attempts = 0;
        const MAX_RETRIES = 3;

        while (attempts < MAX_RETRIES) {
          try {
            const chat = model.startChat({ history: [] });
            const result = await chat.sendMessage(prompt);
            const rawResponse = await result.response.text();

            const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
            let recommendation;

            try {
              recommendation = JSON.parse(sanitizedResponse);
            } catch (parseError) {
              throw new Error('Invalid JSON response from AI');
            }

            return recommendation;
          } catch (error) {
            attempts++;
            if (attempts === MAX_RETRIES) {
              throw new Error('Failed to generate AI recommendation after multiple attempts');
            }
            await new Promise(resolve => setTimeout(resolve, 2000)); // Retry delay
          }
        }
      };

      // Get AI-recommended Pomodoro times
      const aiRecommendation = await generateRecommendationsWithRetry();
      console.log('AI Recommendation:', aiRecommendation);
      res.json(aiRecommendation); // Return AI recommendation to frontend
    });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/flashcard/ai-explanation', async (req, res) => {


  try {


    // Get the flashcard data from the request body
    const { question, answer } = req.body;

    // AI Prompt
    const prompt = `You are an AI tutor. The following is a question and its answer. Please generate an explanation for the answer and explain why it is correct in simple terms:

    Question: ${question}
    Answer: ${answer}

    Explanation: `;

    console.log('Generating AI explanation for flashcard', question);

    // AI Integration & Retry Logic
    const generateExplanationWithRetry = async () => {
      let attempts = 0;
      const MAX_RETRIES = 5;

      while (attempts < MAX_RETRIES) {
        try {
          const chat = model.startChat({ history: [] });
          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
          let explanation;

          try {
            explanation = sanitizedResponse;
          } catch (parseError) {
            throw new Error('Invalid response from AI');
          }

          return explanation;
        } catch (error) {
          attempts++;
          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate AI explanation after multiple attempts');
          }
          await new Promise(resolve => setTimeout(resolve, 2000)); // Retry delay
        }
      }
    };

    // Get AI-generated explanation
    const aiExplanation = await generateExplanationWithRetry();
    console.log('AI Explanation given');
    res.json({ explanation: aiExplanation }); // Return explanation to frontend
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/quiz/ai-analysis', async (req, res) => {
  try {
    // Get the quiz performance data from the request body
    const { score, userAnswers, correctAnswers, questions, topic } = req.body;

    // Prepare the AI prompt based on the quiz data
    let prompt = `You are an AI tutor analyzing a student's quiz performance. Below is the student's performance on a quiz about ${topic}. Please provide feedback on their weak points and suggest areas to focus on for improvement based on the student's answers and score.

    Score: ${score}%
    
    User's Answers: 
    `;

    questions.forEach(question => {
      const userAnswerId = userAnswers[question.id];
      const correctAnswer = correctAnswers[question.id];
      const isCorrect = userAnswerId === correctAnswer?.id;

      prompt += `\n- Question: ${question.question_text}
      Your Answer: ${question.answers.find(ans => ans.id === userAnswerId)?.answer_text || 'Not Answered'}
      Correct Answer: ${correctAnswer?.text || 'N/A'}
      ${isCorrect ? 'Correct' : 'Incorrect'}`;
    });

    prompt += `\n\nBased on this data, provide a detailed analysis of the student's performance. Highlight the areas where the student struggled and offer suggestions for improvement.`;

    console.log('Generating AI analysis for quiz performance');

    // AI Integration & Retry Logic
    const generateAnalysisWithRetry = async () => {
      let attempts = 0;
      const MAX_RETRIES = 5;

      while (attempts < MAX_RETRIES) {
        try {
          const chat = model.startChat({ history: [] });
          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
          let analysis;

          try {
            analysis = sanitizedResponse;
          } catch (parseError) {
            throw new Error('Invalid response from AI');
          }

          return analysis;
        } catch (error) {
          attempts++;
          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to generate AI analysis after multiple attempts');
          }
          await new Promise(resolve => setTimeout(resolve, 2000)); // Retry delay
        }
      }
    };

    // Get AI-generated analysis
    const aiAnalysis = await generateAnalysisWithRetry();
    console.log('AI Analysis generated');

    res.json({ analysis: aiAnalysis }); // Return analysis to frontend
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


const generateWithRetry = async (prompt) => {
  let attempts = 0;
  const MAX_RETRIES = 5;

  while (attempts < MAX_RETRIES) {
    try {
      const chat = model.startChat({ history: [] });
      const result = await chat.sendMessage(prompt);
      const rawResponse = await result.response.text();

      const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();

      return sanitizedResponse; 
    } catch (error) {
      attempts++;
      if (attempts === MAX_RETRIES) {
        throw new Error('Failed to generate AI response after multiple attempts');
      }
      await new Promise(resolve => setTimeout(resolve, 2000)); // Retry delay
    }
  }
};


app.post('/api/question-paper/generate', async (req, res) => {
  try {
    const { subject, chapters, board, grade, token } = req.body;
    if (!subject || !chapters || !board || !grade || !token) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const userId = await getUserIdFromToken(token);

    let prompt = '';
    const competitiveExams = ['JEE Mains', 'JEE Advanced', 'NEET', 'CUET', 'GATE', 'UPSC', 'CAT', 'SAT', 'GRE', 'GMAT'];

    // Adjust difficulty level based on board
    const difficultyLevel = competitiveExams.includes(board) ? 'very hard' : 'moderate';

    // Generate prompt based on board
    if (competitiveExams.includes(board)) {
      // Competitive Exam Format (e.g., NEET, JEE)
      prompt = `
      Generate a **competitive exam question paper** for **${subject}**.
      **Exam:** ${board}
      **Chapters:** ${chapters.join(', ')}
      **Grade:** ${grade}
      
      **Difficulty Level:** ${difficultyLevel} (Please ensure the questions are challenging enough for ${board})
      
      Generate 6 questions in total with 4 main sections:
      - Section 1: 2 MCQs (multiple-choice questions)
      - Section 2: 2 short-answer questions
      - Section 3: 1 long-answer question
      - Section 4: 1 reasoning-based question

      Please ensure all questions are of appropriate difficulty for the ${board} exam. Questions should be in-depth and require critical thinking. Do not include answers or any extra text, formatting, or instructions. Just the questions.

      --- 

      <h2>${board} - ${subject} (Grade ${grade})</h2>

      <h3>Section 1: Multiple-Choice Questions (MCQs)</h3>
      <ol>
        <li>MCQ 1 for ${subject}</li>
        <li>MCQ 2 for ${subject}</li>
      </ol>

      <h3>Section 2: Short Answer Questions</h3>
      <ol>
        <li>Short Answer 1 for ${subject}</li>
        <li>Short Answer 2 for ${subject}</li>
      </ol>

      <h3>Section 3: Long Answer Question</h3>
      <ol>
        <li>Long Answer Question for ${subject}</li>
      </ol>

      <h3>Section 4: Reasoning-Based Question</h3>
      <ol>
        <li>Reasoning Question for ${subject}</li>
      </ol>
      `;
    } else {
      // School Board Format (e.g., CBSE, ICSE)
      prompt = `
      Generate a **school board question paper** for **${subject}**.
      **Chapters:** ${chapters.join(', ')}
      **Board:** ${board}, **Grade:** ${grade}
      
      **Difficulty Level:** ${difficultyLevel} (Please ensure the questions are appropriately challenging for ${board})
      
      Generate 6 questions in total with 4 main sections:
      - Section 1: 2 MCQs
      - Section 2: 2 short-answer questions
      - Section 3: 1 long-answer question
      - Section 4: 1 reasoning-based question

      Do not include answers or any extra text, formatting, or instructions. Just the questions.

      --- 

      <h2>${board} - ${subject} (Grade ${grade})</h2>

      <h3>Section 1: Multiple-Choice Questions (MCQs)</h3>
      <ol>
        <li>MCQ 1 for ${subject}</li>
        <li>MCQ 2 for ${subject}</li>
      </ol>

      <h3>Section 2: Short Answer Questions</h3>
      <ol>
        <li>Short Answer 1 for ${subject}</li>
        <li>Short Answer 2 for ${subject}</li>
      </ol>

      <h3>Section 3: Long Answer Question</h3>
      <ol>
        <li>Long Answer Question for ${subject}</li>
      </ol>

      <h3>Section 4: Reasoning-Based Question</h3>
      <ol>
        <li>Reasoning Question for ${subject}</li>
      </ol>
      `;
    }

    console.log('Generating question paper');
    const questionPaper = await generateWithRetry(prompt);

    const answerPrompt = `
    Generate **detailed answers** for the following question paper in **HTML format**:
    - **Use HTML tags** to properly format answers. Do not use markdown, asterisks, or plain text.
    - Make sure to clearly show all steps and reasoning, including explanations for formulas and any necessary units.
    - Format each question and answer separately with proper use of HTML elements like <h3>, <p>, <ol>, <li>, <strong>, and <em> for clarity.
    - Keep explanations educational, concise, and focused on step-by-step reasoning.
    
    ### Question Paper:
    ${questionPaper}
    
    Ensure each answer is clearly explained and formatted with proper HTML structure.
    `;
    
    console.log('Generating answers for the question paper');
    const answers = await generateWithRetry(answerPrompt);
    

    // 📌 Insert into Database with Answers
    const result = await query(
      'INSERT INTO question_papers (user_id, subject, board, grade, questions, answers) VALUES (?, ?, ?, ?, ?, ?)', 
      [userId, subject, board, grade, questionPaper, answers]
    );

    const questionPaperId = result.insertId;

    res.json({ 
      message: 'Question paper generated successfully', 
      questionPaper: { id: questionPaperId, content: questionPaper, answers: answers } 
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to generate question paper' });
  }
});



// **Fetch User's Question Papers**
app.get('/api/question-paper/user', async (req, res) => {
  try {
    const { token } = req.headers;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const userId = await getUserIdFromToken(token);
    const papers = await query('SELECT * FROM question_papers WHERE user_id = ?', [userId]);

    res.json({ questionPapers: papers });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to fetch question papers' });
  }
});

app.post('/api/get-user-paper-count', async (req, res) => {  // Change GET to POST
  try {
    const { token } = req.body;  // Extract token from the request body

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = await getUserIdFromToken(token);  // Get userId from the token

    // SQL query to count the number of papers for the given user
    const query = 'SELECT COUNT(*) AS paperCount FROM question_papers WHERE user_id = ?';

    // Execute the query
    connection.execute(query, [userId], (err, results) => {
      if (err) {
        console.error('Error fetching paper count:', err);
        return res.status(500).json({ message: 'Server error' });
      }

      // Send the result back to the frontend
      const paperCount = results[0].paperCount;
      res.status(200).json({ paperCount });
    });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/test/generate', async (req, res) => {
  const { subject, chapters, numQuestions, difficulty, timeLimit, token } = req.body;

  try {
      const userId = await getUserIdFromToken(token);
      if (!userId) return res.status(401).json({ error: 'Invalid token' });

      const limitedQuestions = Math.min(numQuestions, 25);
      
      const prompt = `
      Generate ${limitedQuestions} test questions on:
      - Subject: ${subject}
      - Chapters: ${chapters}
      - Difficulty: ${difficulty}
      - Include MCQs & typing questions.
      - Use JSON format.

      Format:
      [
          {
              "question": "string",
              "type": "mcq" | "typing",
              "options": ["option1", "option2", "option3", "option4"], // Only for MCQs
              "correct_answer": "string"
          }
      ]
      `;

      console.log('Generating test with AI...');

      const generateTestWithRetry = async () => {
          let attempts = 0;
          while (attempts < MAX_RETRIES) {
              try {
                  const chat = model.startChat({ history: [] });
                  const result = await chat.sendMessage(prompt);
                  const rawResponse = await result.response.text();
                  const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
                  return JSON.parse(sanitizedResponse);
              } catch (error) {
                  attempts++;
                  if (attempts === MAX_RETRIES) throw new Error('Failed to generate test');
              }
          }
      };

      const testQuestions = await generateTestWithRetry();

      const testResult = await query(
          'INSERT INTO tests (subject, chapters, user_id, difficulty, time_limit) VALUES (?, ?, ?, ?, ?)',
          [subject, chapters, userId, difficulty, timeLimit]
      );

      const testId = testResult.insertId;

      for (const question of testQuestions) {
          const questionResult = await query(
              'INSERT INTO test_questions (test_id, question_text, question_type, correct_answer) VALUES (?, ?, ?, ?)',
              [testId, question.question, question.type, question.correct_answer]
          );

          const questionId = questionResult.insertId;

          if (question.type === 'mcq') {
              for (const option of question.options) {
                  await query(
                      'INSERT INTO test_options (question_id, option_text) VALUES (?, ?)',
                      [questionId, option]
                  );
              }
          }
      }

      res.json({ message: 'Test generated successfully', testId, testQuestions });
  } catch (error) {
      console.error('Error generating test:', error);
      res.status(500).json({ error: 'Error generating test' });
  }
});


app.post('/api/test/submit', async (req, res) => {
  const { testId, answers, token } = req.body;

  console.log('Received request:', { testId, answers, token });

  try {
      const userId = await getUserIdFromToken(token);
      if (!userId) return res.status(401).json({ error: 'Invalid token' });

      if (!Array.isArray(answers) || answers.length === 0) {
          return res.status(400).json({ error: 'Answers must be a non-empty array' });
      }

      let totalQuestions = answers.length;
      let totalCorrectAnswers = 0;

      // Prepare the prompt for AI evaluation
      const evaluationPrompt = answers.map(answer => ({
          questionId: answer.questionId,
          userAnswer: answer.userAnswer
      }));

      // Generate the AI evaluation prompt
      const prompt = `
      Evaluate the following answers for the test:
      Questions: 
      ${JSON.stringify(evaluationPrompt)}

      For each answer, provide the following:
      - Correctness: Is the answer correct? (Yes/No)
      - Explanation: Explain why the answer is correct or incorrect.
      - Tips: Provide any additional tips to improve the user's understanding.
      
      Format the response as a JSON array:
      [
          {
              "questionId": "string",
              "isCorrect": "Yes" | "No",
              "explanation": "string",
              "tips": "string"
          }
      ]
      `;

      console.log('Evaluating answers with AI...');

      // AI call to evaluate answers
      const evaluateAnswersWithRetry = async () => {
          let attempts = 0;
          while (attempts < MAX_RETRIES) {
              try {
                  const chat = model.startChat({ history: [] });
                  const result = await chat.sendMessage(prompt);
                  const rawResponse = await result.response.text();
                  const sanitizedResponse = rawResponse.replace(/```(?:json)?/g, '').trim();
                  return JSON.parse(sanitizedResponse);
              } catch (error) {
                  attempts++;
                  if (attempts === MAX_RETRIES) throw new Error('Failed to evaluate answers');
              }
          }
      };

      const evaluationResults = await evaluateAnswersWithRetry();

      // Store the evaluation results and score in the database
      let totalCorrect = 0;
      for (const result of evaluationResults) {
          const { questionId, isCorrect, explanation, tips } = result;

          // Save the evaluation details (correctness, explanation, tips) using promisified query
          await query(
              'INSERT INTO test_answers (test_id, question_id, is_correct, explanation, tips) VALUES (?, ?, ?, ?, ?)',
              [testId, questionId, isCorrect === "Yes", explanation, tips]
          );

          if (isCorrect === "Yes") totalCorrect++;
      }

      const score = (totalCorrect / totalQuestions) * 100;

      // Update the test score using promisified query
      await query('UPDATE tests SET score = ? WHERE id = ?', [score, testId]);

      res.json({ message: 'Test submitted and evaluated successfully', score, evaluationResults });
  } catch (error) {
      console.error('Error submitting and evaluating test:', error);
      res.status(500).json({ error: 'Error submitting and evaluating test' });
  }
});

app.post('/api/quiz/generate/exam', async (req, res) => {
  const { examType, subjects, chapters, token } = req.body;


  try {
    // Step 1: Retrieve userId from the token
    const userId = await getUserIdFromToken(token);
    console.log(`Generating Mock Quiz for ${examType}...`);

    const difficultyMapping = {
      NEET: "High conceptual + medical-level reasoning",
      JEE: "Math-intensive + logical thinking",
      UPSC: "Analytical + fact-based reasoning",
      CAT: "Quantitative Aptitude + Logical Reasoning",
      GATE: "Engineering-level conceptual questions",
      GMAT: "Verbal reasoning + Data Interpretation",
      GRE: "Analytical Writing + Logical Reasoning",
      SAT: "High-school level critical thinking",
      CLAT: "Legal aptitude + Logical reasoning",
      Banking: "Quantitative Aptitude + Financial Awareness",
      SSC: "General Knowledge + Numerical Ability",
      CUET: "University entrance level subject-based reasoning"
    };
    
    const difficulty = difficultyMapping[examType] || "General competitive level";

    // Function to generate a batch of 10 questions
    const generateQuizBatch = async (batchSize) => {
      const prompt = `
      Generate exactly **${batchSize}** high-quality **MCQs, Assertion-Reasoning, Fill-in-the-Blanks, and Numerical** questions in **valid JSON format**.
      
      ### Exam Details:
      - **Exam Type**: ${examType}
      - **Subjects**: ${subjects.join(", ")}
      - **Chapters**: ${chapters.join(", ")}
      - **Difficulty Level**: ${difficulty}

      ### **JSON Format (Strictly return only the array)**:
    [
  {
    "type": "MCQ",
    "question": "What is the acceleration due to gravity on Earth?",
    "options": ["8.9 m/s²", "9.8 m/s²", "10.2 m/s²", "7.5 m/s²"],
    "correct_answer": "9.8 m/s²",
    "difficulty": "Easy",
    "time_limit": "30"
  },
  {
    "type": "Assertion-Reasoning",
    "question": "Assertion: The boiling point of water decreases at higher altitudes. Reason: Atmospheric pressure decreases as altitude increases.",
    "options": [
      "Both are true, and reason explains assertion",
      "Both are true, but reason does not explain assertion",
      "Assertion is true, but reason is false",
      "Both are false"
    ],
    "correct_answer": "Both are true, and reason explains assertion",
    "difficulty": "Medium",
    "time_limit": "40"
  },
  {
    "type": "Fill-in-the-blank",
    "question": "The chemical formula of water is ____.",
    "options": ["H2O", "CO2", "O2", "H2O2"],
    "correct_answer": "H2O",
    "difficulty": "Easy",
    "time_limit": "30"
  },
  {
    "type": "Numerical",
    "question": "A car starts from rest and accelerates at 5 m/s² for 4 seconds. What is its final velocity?",
    "options": ["10 m/s", "15 m/s", "20 m/s", "25 m/s"],
    "correct_answer": "20 m/s",
    "difficulty": "Medium",
    "time_limit": "50"
  },
       // ${batchSize - 1} more questions
]

      ### **Rules**:
      1. **Return exactly ${batchSize} questions—no more, no less.**
      2. **Mix of 40% MCQs, 20% Assertion-Reasoning, 20% Fill-in-the-Blanks, 20% Numerical.**
      3. **All questions must have exactly 4 answer choices, including numerical ones.**
      4. **No explanations, comments, or extra text—only valid JSON.**
      `.trim();

      let attempts = 0;
      const MAX_RETRIES = 3;

      while (attempts < MAX_RETRIES) {
        try {
          // Call AI model
          const chat = model.startChat({
            history: [
              { role: 'user', parts: [{ text: 'Hello' }] },
              { role: 'model', parts: [{ text: 'I can generate high-quality quizzes for competitive exams!' }] },
            ],
          });

          const result = await chat.sendMessage(prompt);
          const rawResponse = await result.response.text();

          // Sanitize JSON
          const sanitizedResponse = rawResponse
            .replace(/```(?:json)?/g, '')  // Remove markdown code blocks
            .replace(/\,[\s\r\n]*\]/g, ']') // Fix trailing commas
            .trim();

          // Parse and validate JSON
          let quizQuestions = JSON.parse(sanitizedResponse);
          if (Array.isArray(quizQuestions) && quizQuestions.length === batchSize) {
            return quizQuestions;
          } else {
            console.error(`AI returned incorrect number of questions. Retrying...`);
            attempts++;
          }
        } catch (error) {
          console.error(`Attempt ${attempts + 1} failed:`, error);
          attempts++;
          await delay(2000); // Wait 2 seconds before retrying
        }
      }
      
      throw new Error('Failed to generate quiz batch after multiple attempts');
    };

    // Step 4: Generate quiz in 3 batches of 10 questions each
    let quizQuestions = [];
    for (let i = 0; i < 5; i++) {
      const batch = await generateQuizBatch(10);
      quizQuestions = quizQuestions.concat(batch);
    }

    // Step 5: Insert quiz details into the database
    const title = `${examType} Quiz`;
    const description = `Quiz for ${examType} covering ${subjects.join(", ")} - ${chapters.join(", ")}`;
    const [quizResult] = await connection.promise().query(
      'INSERT INTO quizzes (title, description, creator_id, is_competive, type) VALUES (?, ?, ?, ?, ?)',
      [title, description, userId, 1, examType]
    );
    
    const quizId = quizResult.insertId;

    // Step 6: Insert questions and answers into the database
    for (const question of quizQuestions) {
      const [questionResult] = await connection.promise().query(
        'INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)',
        [quizId, question.question]
      );
      const questionId = questionResult.insertId;

      for (const option of question.options) {
        const isCorrect = option === question.correct_answer;
        await connection.promise().query(
          'INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)',
          [questionId, option, isCorrect]
        );
      }
    }
    console.log('Competitive exam quiz generated successfully!');

    // Step 7: Return the quiz details
    res.json({ message: 'Competitive exam quiz generated successfully', quizId });
  } catch (error) {
    console.error('Error generating quiz:', error);
    res.status(500).json({ error: 'Error generating quiz' });
  }
});

app.post('/submitCompetitiveQuiz', async (req, res) => {
  const { token, quizId, type, answers } = req.body;

  // Validate input
  if (!token || typeof token !== 'string' || !quizId || typeof quizId !== 'number' || !Array.isArray(answers) || !type) {
    console.error('Invalid input data:', req.body);
    return res.status(400).json({ message: 'Invalid input data' });
  }

  try {
    const userId = await getUserIdFromToken(token);
    let correctCount = 0;
    let incorrectCount = 0;
    let answerResults = [];

    // Step 1: Check answers and collect results
    for (const answer of answers) {
      if (typeof answer.answerId !== 'number' || typeof answer.questionId !== 'number') {
        console.error('Invalid answer format:', answer);
        return res.status(400).json({ message: 'Invalid answer format' });
      }

      const [result] = await connection.promise().query(
        'SELECT id FROM answers WHERE question_id = ? AND is_correct = TRUE',
        [answer.questionId]
      );

      if (result.length) {
        const correctAnswerId = result[0].id;
        const isCorrect = correctAnswerId === answer.answerId;

        answerResults.push({
          questionId: answer.questionId,
          userAnswerId: answer.answerId,
          correctAnswerId: correctAnswerId,
          isCorrect: isCorrect,
        });

        if (isCorrect) correctCount++;
        else incorrectCount++;
      }
    }

    // Step 2: Get total questions
    const [questions] = await connection.promise().query(
      'SELECT COUNT(*) AS count FROM questions WHERE quiz_id = ?',
      [quizId]
    );

    const totalQuestions = questions[0].count;
    if (totalQuestions === 0) {
      return res.status(400).json({ message: 'No questions found for this quiz' });
    }

   // Step 3: Apply scoring system based on `type`
let score = 0;
let maxMarksPerQuestion = 1; // Default max marks per question

switch (type) {
  case 'NEET':
  case 'JEE':
    score = correctCount * 4 - incorrectCount * 1;
    maxMarksPerQuestion = 4;
    break;
  case 'UPSC':
  case 'SSC':
  case 'Banking':
    score = correctCount * 2 - incorrectCount * 0.66;
    maxMarksPerQuestion = 2;
    break;
  case 'CAT':
  case 'CUET':
    score = correctCount * 3 - incorrectCount * 1;
    maxMarksPerQuestion = 3;
    break;
  case 'GATE':
    score = correctCount * 2 - incorrectCount * 0.33;
    maxMarksPerQuestion = 2;
    break;
  case 'GMAT':
  case 'GRE':
  case 'SAT':
    score = correctCount * 1 - incorrectCount * 0.25;
    maxMarksPerQuestion = 1;
    break;
  case 'CLAT':
    score = correctCount * 1 - incorrectCount * 0.5;
    maxMarksPerQuestion = 1;
    break;
  default:
    score = (correctCount / totalQuestions) * 100; // Default percentage score
}

// Ensure score never exceeds 100% of total possible marks
const maxPossibleScore = totalQuestions * maxMarksPerQuestion;
score = Math.min(score, maxPossibleScore);


    // **No longer preventing negative scores**
    
    // Step 4: Save score to `user_quizzes`
    await connection.promise().query(
      'INSERT INTO user_quizzes (user_id, quiz_id, score) VALUES (?, ?, ?)',
      [userId, quizId, score]
    );

    // Step 5: Update Points System (only if score is positive)
    if (score > 0) {
      const pointsEarned = correctCount * 5; // 5 points per correct answer
      const pointsQuery = 'SELECT * FROM user_points WHERE user_id = ?';
      const [pointsResults] = await connection.promise().query(pointsQuery, [userId]);

      if (pointsResults.length > 0) {
        await connection.promise().query('UPDATE user_points SET points = points + ? WHERE user_id = ?', [pointsEarned, userId]);
      } else {
        await connection.promise().query('INSERT INTO user_points (user_id, points) VALUES (?, ?)', [userId, pointsEarned]);
      }
    }

    res.json({ score, answerResults });

  } catch (error) {
    console.error('Error submitting competitive quiz:', error.message);
    res.status(500).json({ message: 'Error submitting competitive quiz' });
  }
});

// Fetch Approved Resources
app.get("/api/resources", (req, res) => {
  const query = `SELECT * FROM resources WHERE status = 'approved' ORDER BY created_at DESC`;
  connection.query(query, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
  });
});

// Smart Search
app.get("/api/resources/search", (req, res) => {
  const { query } = req.query;
  const searchQuery = `SELECT * FROM resources WHERE status = 'approved' 
      AND (title LIKE ? OR description LIKE ?)`;
  const searchTerm = `%${query}%`;
  connection.query(searchQuery, [searchTerm, searchTerm], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
  });
});

// Submit a New Resource (User Suggestion)
app.post("/api/resources/add", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Extract token from header
  if (!token) {
      return res.status(401).json({ error: "Unauthorized. Token missing." });
  }

  try {
      const userId = await getUserIdFromToken(token); // Get user_id from token
      if (!userId) {
          return res.status(401).json({ error: "Invalid or expired token." });
      }

      const { title, description, link, category } = req.body; // Added category field

      if (!category) {
          return res.status(400).json({ error: "Category is required." });
      }

      const query = "INSERT INTO resources (title, description, link, category, user_id) VALUES (?, ?, ?, ?, ?)";

      connection.query(query, [title, description, link, category, userId], (err, result) => {
          if (err) return res.status(500).json({ error: err.message });

          // Log the review pending message with category
         console.log(`Review pending for a resource: "${title}" (Category: "${category}") by User ID: ${userId}`);

          res.json({ message: "Resource submitted for review!" });
      });
  } catch (error) {
      res.status(500).json({ error: "Internal server error" });
  }
});


app.get("/api/resources/pending", (req, res) => {
  const query = "SELECT * FROM resources WHERE status = 'pending'";
  
  connection.query(query, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
  });
});

app.post("/api/resources/review", (req, res) => {
  const { resourceId, action } = req.body; // action = "approve" or "delete"

  if (action === "approve") {
      const query = "UPDATE resources SET status = 'approved' WHERE id = ?";
      
      connection.query(query, [resourceId], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: "Resource approved successfully!" });
      });

  } else if (action === "delete") {
      const query = "DELETE FROM resources WHERE id = ?";
      
      connection.query(query, [resourceId], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: "Resource deleted successfully!" });
      });

  } else {
      res.status(400).json({ error: "Invalid action" });
  }
});

app.post("/api/resources/toggle-save", async (req, res) => {
  try {
      const { resourceId } = req.body;
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ message: "Unauthorized" });

      const userId = await getUserIdFromToken(token);
      if (!userId) return res.status(403).json({ message: "Invalid token" });

      // Check if the resource is already saved
      const checkQuery = "SELECT * FROM saved_resources WHERE user_id = ? AND resource_id = ?";
      const existing = await query(checkQuery, [userId, resourceId]);

      if (existing.length > 0) {
          // Resource is already saved, so unsave it
          console.log(`UNSAVING resource: ${resourceId} for user: ${userId}`);
          
          const deleteQuery = "DELETE FROM saved_resources WHERE user_id = ? AND resource_id = ?";
          await query(deleteQuery, [userId, resourceId]);

          return res.json({ message: "Resource unsaved successfully", saved: false });
      } else {
          // Resource is not saved, so save it
          console.log(`SAVING resource: ${resourceId} for user: ${userId}`);
          
          const insertQuery = "INSERT INTO saved_resources (user_id, resource_id) VALUES (?, ?)";
          await query(insertQuery, [userId, resourceId]);

          return res.json({ message: "Resource saved successfully", saved: true });
      }
  } catch (error) {
      console.error("Error toggling saved resource:", error);
      res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/api/resources/saved", async (req, res) => {
  try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ message: "Unauthorized" });

      const userId = await getUserIdFromToken(token);
      if (!userId) return res.status(403).json({ message: "Invalid token" });

      const savedResources = await query(
          "SELECT resource_id FROM saved_resources WHERE user_id = ?",
          [userId]
      );

      res.json(savedResources);
  } catch (error) {
      console.error("Error fetching saved resources:", error);
      res.status(500).json({ message: "Internal Server Error" });
  }
});


app.post("/api/resources/click", async (req, res) => {
  const { resourceId } = req.body;

  if (!resourceId) {
      return res.status(400).json({ error: "Resource ID is required" });
  }

  try {
      // Increment the click count
      const updateQuery = "UPDATE resources SET click_count = click_count + 1 WHERE id = ?";
      connection.query(updateQuery, [resourceId], (err, result) => {
          if (err) {
              return res.status(500).json({ error: "Database error" });
          }

          if (result.affectedRows > 0) {
              // Fetch the updated click count
              const fetchQuery = "SELECT click_count FROM resources WHERE id = ?";
              connection.query(fetchQuery, [resourceId], (fetchErr, fetchResult) => {
                  if (fetchErr) {
                      console.error("❌ Error fetching updated click count:", fetchErr);
                      return res.status(500).json({ error: "Database error" });
                  }

                  const newClickCount = fetchResult[0]?.click_count || 0;
                  console.log(`Click count updated for Resource ID: ${resourceId}. New count: ${newClickCount}`);

                  res.json({ message: "Click counted successfully!", click_count: newClickCount });
              });
          } else {
              res.status(404).json({ error: "Resource not found" });
          }
      });
  } catch (error) {
      console.error("❌ Internal server error:", error);
      res.status(500).json({ error: "Internal server error" });
  }
});


app.post("/api/resources/ai-finder", async (req, res) => {
  try {
      const { query } = req.body;
      if (!query) {
          return res.status(400).json({ error: "Query is required" });
      }

      // Fetch all resources with save count
      const fetchQuery = `
          SELECT r.*, 
                 (SELECT COUNT(*) FROM saved_resources WHERE resource_id = r.id) AS save_count
          FROM resources r
      `;

      connection.query(fetchQuery, async (err, results) => {
          if (err) {
              console.error("❌ Database error:", err);
              return res.status(500).json({ error: "Database error" });
          }

          // Rank resources based on keyword relevance & saves
          const rankedResources = results
              .map(resource => {
                  let score = (resource.save_count || 0) * 10; // Boost by saves
                  const keywords = query.toLowerCase().split(" ");

                  keywords.forEach(word => {
                      if (resource.title.toLowerCase().includes(word)) score += 5;
                      if (resource.description.toLowerCase().includes(word)) score += 3;
                      if (resource.category.toLowerCase().includes(word)) score += 2;
                  });

                  return { ...resource, score };
              })
              .sort((a, b) => b.score - a.score)
              .slice(0, 5);

          // AI Prompt
          let prompt = `You are an AI study assistant helping students find the best resources.\nStudent's query: "${query}"\n\nBest resources found:\n`;

          rankedResources.forEach((res, index) => {
              prompt += `${index + 1}. ${res.title}\nCategory: ${res.category}\nDescription: ${res.description}\nLink: ${res.link}\nSaves: ${res.save_count}\n\n`;
          });

          prompt += "Summarize these resources and explain their relevance in simple, clear text. Do not use markdown symbols like *, **, or ```.";

          console.log("Generating AI resources ...", query);

          // AI Integration with Retry Logic
          const generateResponse = async () => {
              for (let attempts = 0; attempts < 5; attempts++) {
                  try {
                      const chat = model.startChat({ history: [] });
                      const result = await chat.sendMessage(prompt);
                      return result.response.text().replace(/```(?:json)?/g, "").trim();
                  } catch (error) {
                      if (attempts === 4) throw new Error("AI response generation failed");
                      await new Promise(resolve => setTimeout(resolve, 2000));
                  }
              }
          };

          const aiResponse = await generateResponse();
          console.log("✅ AI response generated!");

          res.json({ recommendations: aiResponse, resources: rankedResources });
      });
  } catch (error) {
      console.error("❌ Internal server error:", error);
      res.status(500).json({ error: "Internal server error" });
  }
});


// API to update user's location
app.post("/update-location", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Extract token

  if (!token) {
    return res.status(401).send({ error: "No token provided" });
  }

  try {
    const userId = await getUserIdFromToken(token);
    const { latitude, longitude } = req.body;

    if (!latitude || !longitude) {
      return res.status(400).send({ error: "Missing required fields" });
    }

    // Create location string
    const location = `${latitude},${longitude}`;

    // Update user's location in the database
    const query = "UPDATE users SET location = ? WHERE id = ?";
    connection.query(query, [location, userId], (err, result) => {
      if (err) {
        return res.status(500).send({ error: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).send({ error: "User not found" });
      }

      console.log(`Location updated for user ${userId}: ${latitude}, ${longitude}`)
      res.status(200).send({ message: "Location updated successfully" });
    });
  } catch (error) {
    res.status(401).send({ error: "Invalid token" });
  }
});



// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

