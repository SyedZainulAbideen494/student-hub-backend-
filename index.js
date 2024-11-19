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

// Initialize Google Generative AI
const genAI = new GoogleGenerativeAI('AIzaSyDEb3nt1CCmUgQDIsEB1tvsgLzbWHmcYic');

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



const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro", safetySettings: safetySettings });


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
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5 MB
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
      pass: 'kjcr qfwn bueu tjyg',
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
        pointsToAdd = 2; // Or any number you choose
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
              const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000); // Subtract 5 minutes
              let pointsToAdd = 3; // Default points to add

              if (pointsResults.length > 0) {
                  // If user exists, check updated_at timestamp
                  const lastUpdated = new Date(pointsResults[0].updated_at);
                  if (lastUpdated > fiveMinutesAgo) {
                      // If last update was less than 5 minutes ago, add fewer points
                      pointsToAdd = 1; // Or any number you choose
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

    // Step 2: Group tasks by user
    const userTasks = tasks.reduce((acc, task) => {
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

    // Step 3: Send emails to each user
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
    const imageNames = req.files ? req.files.map(file => file.filename) : [];

    console.log('Image filenames:', imageNames); // Log image filenames

    // Step 2: Update the SQL query to include subjectId
    const query = `
      INSERT INTO flashcards (title, description, images, is_public, user_id, headings, subject_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?) 
    `;
    const values = [title, description, JSON.stringify(imageNames), isPublic, userId, headings, subjectId];

    connection.query(query, values, (error) => {
      if (error) {
        console.error('Error inserting flashcard:', error);
        return res.status(500).json({ message: 'Failed to save flashcard.' });
      }

      // Step 3: Update Points
      const pointsQuery = 'SELECT points, updated_at FROM user_points WHERE user_id = ?';
      connection.query(pointsQuery, [userId], (err, pointsResults) => {
        if (err) {
          console.error('Error fetching user points:', err);
          return res.status(500).json({ message: 'Failed to update points.' });
        }

        const currentTime = new Date();
        const fiveMinutesAgo = new Date(currentTime.getTime() - 5 * 60000); // Subtract 5 minutes
        let pointsToAdd = 10; // Default points to add

        if (pointsResults.length > 0) {
          // If user exists, check updated_at timestamp
          const lastUpdated = new Date(pointsResults[0].updated_at);
          if (lastUpdated > fiveMinutesAgo) {
            // If last update was less than 5 minutes ago, add fewer points
            pointsToAdd = 2; // Or any number you choose
          }

          // Update points and set the updated_at timestamp
          connection.query(
            'UPDATE user_points SET points = points + ?, updated_at = ? WHERE user_id = ?',
            [pointsToAdd, currentTime, userId],
            (err) => {
              if (err) {
                console.error('Error updating points:', err);
                return res.status(500).json({ message: 'Failed to update points.' });
              }
              res.status(200).json({ message: 'Flashcard saved successfully! Points updated.' });
            }
          );
        } else {
          // If user does not exist, insert new record with the points
          connection.query(
            'INSERT INTO user_points (user_id, points, updated_at) VALUES (?, ?, ?)',
            [userId, pointsToAdd, currentTime],
            (err) => {
              if (err) {
                console.error('Error inserting points:', err);
                return res.status(500).json({ message: 'Failed to update points.' });
              }
              res.status(200).json({ message: 'Flashcard saved successfully! Points added.' });
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
    let pointsToAdd = 8; // Default points to add

    if (pointsResults.length > 0) {
      // If user exists, check updated_at timestamp
      const lastUpdated = new Date(pointsResults[0].updated_at);
      if (lastUpdated > fiveMinutesAgo) {
        // If last update was less than 5 minutes ago, add fewer points
        pointsToAdd = 2; // Or any number you choose
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

    // Step 1: Check answers
    for (const answer of answers) {
      if (typeof answer.answerId !== 'number' || typeof answer.questionId !== 'number') {
        console.error('Invalid answer format:', answer);
        return res.status(400).json({ message: 'Invalid answer format' });
      }

      const [result] = await connection.promise().query(
        'SELECT * FROM answers WHERE id = ? AND question_id = ? AND is_correct = TRUE',
        [answer.answerId, answer.questionId]
      );

      if (result.length) correctCount++;
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
      await connection.promise().query('UPDATE user_points SET points = points + 5 WHERE user_id = ?', [userId]);
    } else {
      // If user does not exist, insert new record with 15 points
      await connection.promise().query('INSERT INTO user_points (user_id, points) VALUES (?, ?)', [userId, 15]);
    }

    res.json({ score });

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
        pointsToAdd = 1; // Or any number you choose
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

const clientId = '0aac6cb1ec104103a5e2e5d6f9b490e7';
const clientSecret = '4e2d9a5a3be9406c970cf3f6cb78b7a3';
const redirectUri = `http://localhost:8080/callback`; // Ensure this matches your Spotify Dashboard

app.use(cors());

app.get('/login/spotify', (req, res) => {
  const scope = 'user-read-private user-read-email streaming user-modify-playback-state';
  res.redirect('https://accounts.spotify.com/authorize?' +
    querystring.stringify({
      response_type: 'code',
      client_id: clientId,
      scope: scope,
      redirect_uri: redirectUri
    }));
});

app.get('/callback', (req, res) => {
  const code = req.query.code || null;
  const authOptions = {
    url: 'https://accounts.spotify.com/api/token',
    form: {
      code: code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    },
    headers: {
      'Authorization': 'Basic ' + Buffer.from(clientId + ':' + clientSecret).toString('base64')
    },
    json: true
  };

  request.post(authOptions, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      const access_token = body.access_token;
      const refresh_token = body.refresh_token;

      const uri = 'http://localhost:3000/music';
      res.redirect(uri + '?access_token=' + access_token + '&refresh_token=' + refresh_token);
    } else {
      res.redirect('/#' +
        querystring.stringify({
          error: 'invalid_token'
        }));
    }
  });
});

app.post('/refresh_token', async (req, res) => {
  const { refreshToken } = req.body;

  const authOptions = {
    url: 'https://accounts.spotify.com/api/token',
    form: {
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    },
    headers: {
      'Authorization': 'Basic ' + Buffer.from(clientId + ':' + clientSecret).toString('base64')
    },
    json: true
  };

  request.post(authOptions, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      res.json({ accessToken: body.access_token });
    } else {
      console.error('Error refreshing token:', error);
      res.status(response.statusCode).json({ error: 'Failed to refresh token' });
    }
  });
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
            currency: 'USD',
            product_data: {
              name: 'edusify premium',
              description: 'Unlock premium features of edusify!',
            },
            unit_amount: 118, // Amount in cents (e.g., $1.00)
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


// Function to check and update expired premium accounts
const checkExpiredPremiums = () => {
  const currentDate = new Date();

  const query = `
    UPDATE users 
    SET is_premium = 0 
    WHERE is_premium = 1 AND premium_expiry_date < ?`;

  connection.query(query, [currentDate], (err, results) => {
    if (err) {
      console.error('Error updating expired premium accounts:', err);
    } else {
      console.log(`Updated ${results.affectedRows} expired premium accounts.`);
    }
  });
};

// Schedule the cron job to run every 24 hours (midnight)
cron.schedule('0 0 * * *', () => {
  console.log('Running check for expired premium accounts...');
  checkExpiredPremiums();
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


const MAX_RETRIES = 15;

// Helper function to introduce a delay (in milliseconds)
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

app.post('/api/chat/ai', async (req, res) => {
  const { message, chatHistory, token } = req.body;

  try {
    // Get user ID from token
    const userId = await getUserIdFromToken(token);

    const chat = model.startChat({
      history: chatHistory || [
        {
          role: 'user',
          parts: [{ text: 'Hello' }],
        },
        {
          role: 'model',
          parts: [{ text: 'Great to meet you. What would you like to know?' }],
        },
      ],
    });

    // Log the user's question
    console.log(`User Inquiry: "${message}" | User ID: ${userId}`);


    // Function to attempt sending message and retry on failure
    const sendMessageWithRetry = async (message) => {
      let attempts = 0;

      while (attempts < MAX_RETRIES) {
        try {
          // Attempt to send the message
          const result = await chat.sendMessage(message);
          // If successful, return the response text
          return result.response.text();
        } catch (error) {
          attempts++;
          console.log(`Attempt ${attempts} failed, retrying...`);

          // If we have failed all retry attempts, throw an error
          if (attempts === MAX_RETRIES) {
            throw new Error('Failed to communicate with the AI after multiple attempts');
          }

          // Delay before retrying
          await delay(4000); // Delay for 2 seconds before the next attempt
        }
      }
    };

    // Try to get a response from the AI
    const responseText = await sendMessageWithRetry(message);

    // Log that the AI was asked
    console.log('AI was asked for response.');

    // Store user message and AI response in MySQL
    await query('INSERT INTO ai_history (user_id, user_message, ai_response) VALUES (?, ?, ?)', [userId, message, responseText]);

    res.json({ response: responseText });
  } catch (error) {
    console.error('Error communicating with Gemini API:', error);

    // Provide a default error message
    let errorMessage = 'Failed to communicate with the API';

    // Safely access error response properties
    if (error.response) {
      errorMessage = `Error: ${error.response.status} - ${error.response.data?.message || error.response.statusText}`;
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
      LIMIT 10
  `;

  connection.query(sql, (err, results) => {
      if (err) {
          console.error('Error fetching leaderboard data:', err);
          return res.status(500).json({ error: 'Failed to fetch leaderboard data' });
      }
      res.json(results); // Return the leaderboard data as JSON
  });
});

app.post('/api/flashcards/generate', async (req, res) => {
  const { set_id } = req.body; // Get the set ID from the request body

  try {
    // Fetch the subject and topic based on the set_id
    const setQuery = 'SELECT subject, topic FROM flashcard_sets WHERE id = ?';
    connection.query(setQuery, [set_id], async (err, results) => {
      if (err || results.length === 0) {
        console.error('Error fetching flashcard set:', err);
        return res.status(500).json({ error: 'Flashcard set not found' });
      }

      const { subject, topic } = results[0];

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
    });
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


// Route to fetch stories for the users the current user follows
app.post('/fetchStories', async (req, res) => {
  const { token } = req.body;  // Token from the request body

  try {
    const userId = await getUserIdFromToken(token);
    
    // Fetching the list of following_ids
    const followQuery = 'SELECT following_id FROM followers WHERE follower_id = ?';
    const followingUsers = await query(followQuery, [userId]);

    const followingIds = followingUsers.map(follow => follow.following_id);

    if (followingIds.length === 0) {
      return res.json({ stories: [] });
    }

    // Fetch stories from the followed users (within 24 hours)
    const storyQuery = `
      SELECT s.content, s.story_type, s.expires_at, u.user_name, u.avatar
      FROM stories s
      JOIN users u ON s.user_id = u.id
      WHERE s.user_id IN (?) AND s.expires_at > NOW()
    `;
    const stories = await query(storyQuery, [followingIds]);

    res.json({ stories });
  } catch (error) {
    console.error('Error fetching stories:', error);
    res.status(500).json({ error: 'Failed to fetch stories' });
  }
});


// Add a new story endpoint
app.post('/addStory', upload.single('file'), async (req, res) => {
  const { token } = req.body; // Token in the request body
  const { storyType, content } = req.body;

  try {
    // Get user ID from token
    const userId = await getUserIdFromToken(token);

    // Calculate expiration time (24 hours from now)
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    // Store file path if it's an image or video
    let filePath = null;
    if (req.file) {
      filePath = req.file.path; // Get the file path from the uploaded file
    }

    // Insert new story into the database
    const sql = `
      INSERT INTO stories (user_id, story_type, content, file_path, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `;
    await query(sql, [userId, storyType, content, filePath, expiresAt]);

    res.status(201).json({ message: 'Story uploaded successfully' });
  } catch (error) {
    console.error('Error uploading story:', error);
    res.status(500).json({ error: 'Failed to upload story' });
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
      : `Create a concise task plan in JSON format, breaking down the main task: "${mainTask}" into simple steps for completion within ${days} days. The task plan should include:
          - 'title' summarizing each action
          - 'due_date' in YYYY-MM-DD format, starting from today (${todayDate})
          - Minimal 'description' with only essential steps or resources.`;

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

    // Update user points
    const updatePointsQuery = 'UPDATE user_points SET points = points + 5 WHERE user_id = ?';
    await query(updatePointsQuery, [user_id]);

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
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from "Bearer <token>"
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




// Function to send birthday email
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


// Route to send emails to users
app.post('/send-emails/all-users/admin', async (req, res) => {
  const { content, subject } = req.body;

  try {
      // Fetch all users from the database
      const users = await query('SELECT email, unique_id FROM users', []);

      // Map over users to create personalized emails
      const emailsToSend = users.map((user) => {
          // Replace {{name}} in the email content with the user's unique_id (or name)
          const personalizedContent = content.replace(/{{name}}/g, user.unique_id);

          return {
              from: 'edusyfy@gmail.com', // Sender address
              to: user.email,            // Recipient email
              subject: subject,          // Subject line
              html: personalizedContent, // Email content (HTML format)
          };
      });

      // Send all emails asynchronously using Promise.all
      await Promise.all(emailsToSend.map((email) => transporter.sendMail(email)));

      // Send a success response
      res.status(200).json({ message: 'Emails sent successfully!' });
  } catch (error) {
      console.error('Error sending emails:', error);
      res.status(500).json({ message: 'Error sending emails', error });
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

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

