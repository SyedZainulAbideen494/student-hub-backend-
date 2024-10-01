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


// Initialize Google Generative AI
const genAI = new GoogleGenerativeAI('AIzaSyDNx6QYkHkvFYd8-lc-O1HgFgCDaChGkV0');
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });


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

const BASE_URL = 'https://dropment.online';
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
                res.json({ auth: true, message: "OTP sent for verification", phone: result[0].phone_number });
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
  const { title, description, due_date, priority, token } = req.body;

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
    // If due_date is not provided, set it to the current date and time
    const formattedDueDate = due_date ? due_date : new Date().toISOString().slice(0, 19).replace('T', ' ');

    // Step 3: Insert Task
    const [insertResults] = await connection.promise().query(
      'INSERT INTO tasks (title, description, due_date, priority, user_id) VALUES (?, ?, ?, ?, ?)',
      [title, description, formattedDueDate, priority, user_id]
    );

    // Step 4: Send response
    res.status(201).send({ id: insertResults.insertId, title, description, due_date: formattedDueDate, priority });
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
      const fetchQuery = 'SELECT * FROM tasks WHERE user_id = ?';
      connection.query(fetchQuery, [user_id], (err, results) => {
          if (err) {
              return res.status(500).send(err);
          }
          res.send(results);
      });
  });
});

app.post('/edit/task', (req, res) => {
  const { id, title, description, due_date, priority, token } = req.body;

  const getUserQuery = 'SELECT user_id FROM session WHERE jwt = ?';
  connection.query(getUserQuery, [token], (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      if (results.length === 0) {
          return res.status(404).send({ message: 'User not found' });
      }

      const user_id = results[0].user_id;
      const updateQuery = 'UPDATE tasks SET title = ?, description = ?, due_date = ?, priority = ? WHERE id = ? AND user_id = ?';
      connection.query(updateQuery, [title, description, due_date, priority, id, user_id], (err, results) => {
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
      const deleteQuery = 'DELETE FROM tasks WHERE id = ? AND user_id = ?';
      connection.query(deleteQuery, [id, user_id], (err, results) => {
          if (err) {
              return res.status(500).send(err);
          }
         
          res.send({ message: 'Task deleted successfully' });
      });
  });
});


const MILLISECONDS_IN_A_DAY = 86400000;

// Function to calculate the delay to the target hour (7:00 AM, 3:00 PM, 9:00 PM IST)
const calculateDelayToTime = (targetHour) => {
    const now = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC +5:30
    const nowInIST = new Date(now.getTime() + istOffset);
    const targetTime = new Date();

    // Set the target time (e.g., 7:00 AM, 3:00 PM, 9:00 PM IST)
    targetTime.setHours(targetHour, 0, 0, 0);

    // If the target time has already passed for today, schedule for tomorrow
    if (nowInIST > targetTime) {
        targetTime.setDate(targetTime.getDate() + 1);
    }

    return targetTime - nowInIST; // Return the delay in milliseconds
};

// Main function to check tasks and send reminders
const checkTasksAndSendReminders = () => {
    const today = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC +5:30
    const todayInIST = new Date(today.getTime() + istOffset).toISOString().split('T')[0]; // YYYY-MM-DD
    const tomorrow = new Date(new Date(todayInIST).setDate(new Date(todayInIST).getDate() + 1)).toISOString().split('T')[0];
    const dayAfter = new Date(new Date(todayInIST).setDate(new Date(todayInIST).getDate() + 2)).toISOString().split('T')[0];

    // Query to get tasks due today, tomorrow, or day after
    const tasksQuery = `
        SELECT t.title, t.due_date, u.phone_number, u.email
        FROM tasks t
        JOIN users u ON t.user_id = u.id
        WHERE t.due_date IN (?, ?, ?)
    `;

    // Query to get events on the calendar for today, tomorrow, or day after
    const eventsQuery = `
        SELECT e.title, e.date, u.phone_number, u.email
        FROM events e
        JOIN users u ON e.user_id = u.id
        WHERE e.date IN (?, ?, ?)
    `;

    // Handle tasks
    connection.query(tasksQuery, [todayInIST, tomorrow, dayAfter], (err, taskResults) => {
        if (err) {
            console.error('Error fetching tasks:', err);
            return;
        }

        taskResults.forEach(task => {
            const { phone_number, email, title, due_date } = task;
            const formattedDate = new Date(due_date).toLocaleDateString('en-IN', { 
                day: '2-digit', 
                month: '2-digit', 
                year: 'numeric' 
            });

            let messageBody = `
            <div style="font-family: Arial, sans-serif; line-height: 1.5; padding: 20px;">
                <h2 style="color: #333;">Task Reminder</h2>
                <p style="font-size: 16px;">
                    Hi there!<br><br>
                    This is a friendly reminder that your task "<strong>${title}</strong>" is due on <strong>${formattedDate}</strong>.
                </p>
                <p style="font-size: 16px;">
                    Click the button below to go to your planner and manage your tasks.
                </p>
                <a href="https://edusify.vercel.app/" style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; border-radius: 5px; margin-top: 10px;">
                    Go to Planner
                </a>
            </div>
            `;

            // Send email
            const mailOptions = {
                from: 'edusyfy@gmail.com',
                to: email,
                subject: 'Task Reminder',
                html: messageBody // Use 'html' for HTML formatted emails
            };

            transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    console.log('Error sending email:', err);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        });
    });

    // Handle events
    connection.query(eventsQuery, [todayInIST, tomorrow, dayAfter], (err, eventResults) => {
        if (err) {
            console.error('Error fetching events:', err);
            return;
        }

        eventResults.forEach(event => {
            const { phone_number, email, title, date } = event;
            const formattedDate = new Date(date).toLocaleDateString('en-IN', { 
                day: '2-digit', 
                month: '2-digit', 
                year: 'numeric' 
            });

            let messageBody = `
            <div style="font-family: Arial, sans-serif; line-height: 1.5; padding: 20px;">
                <h2 style="color: #333;">Event Reminder</h2>
                <p style="font-size: 16px;">
                    Hi there!<br><br>
                    This is a friendly reminder that your event "<strong>${title}</strong>" is scheduled for <strong>${formattedDate}</strong>.
                </p>
                <p style="font-size: 16px;">
                    Click the button below to go to your calendar and view your events.
                </p>
                <a href="https://edusify.vercel.app/calendar" style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; border-radius: 5px; margin-top: 10px;">
                    Go to Calendar
                </a>
            </div>
            `;

            // Send email
            const mailOptions = {
                from: 'edusyfy@gmail.com',
                to: email,
                subject: 'Event Reminder',
                html: messageBody // Use 'html' for HTML formatted emails
            };

            transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    console.log('Error sending email:', err);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        });
    });
};

// Function to schedule reminders at specific times
const scheduleReminder = (targetHour) => {
    const initialDelay = calculateDelayToTime(targetHour);
    setTimeout(() => {
        checkTasksAndSendReminders();
        setInterval(checkTasksAndSendReminders, MILLISECONDS_IN_A_DAY);
    }, initialDelay);
};

// Schedule reminders for 7:00 AM, 3:00 PM, and 9:00 PM IST
scheduleReminder(7);   // 7:00 AM IST
scheduleReminder(15);  // 3:00 PM IST
scheduleReminder(21);  // 9:00 PM IST




app.post('/api/add/flashcards', upload.array('images'), (req, res) => {
  const { title, description, isPublic, token, headings } = req.body;

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

      const query = `
          INSERT INTO flashcards (title, description, images, is_public, user_id, headings) 
          VALUES (?, ?, ?, ?, ?, ?)
      `;
      const values = [title, description, JSON.stringify(imageNames), isPublic, userId, headings];

      connection.query(query, values, (error) => {
          if (error) {
              console.error('Error inserting flashcard:', error);
              return res.status(500).json({ message: 'Failed to save flashcard.' });
          }

          res.status(200).json({ message: 'Flashcard saved successfully!' });
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

// Route to update a specific note by note_id
app.put('/api/update/note/:note_id', (req, res) => {
  const noteId = req.params.note_id;
  const { title, description, headings } = req.body;

  const query = `
      UPDATE flashcards 
      SET title = ?, description = ?, headings = ?
      WHERE id = ?
  `;
  const values = [title, description, headings, noteId];

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
              console.error('Error fetching user_id:', err);
              reject(new Error('Failed to authenticate user.'));
          }

          if (results.length === 0) {
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

      // Insert message into the messages table
      const query = 'INSERT INTO messages (sender, group_id, type, content) VALUES (?, ?, ?, ?)';
      connection.query(query, [senderId, groupId, 'flashcard', id], (err, results) => {
          if (err) {
              console.error('Error inserting message:', err);
              return res.status(500).send('Error sharing flashcard');
          }
          res.status(200).send('Flashcard shared successfully');
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

      const [result] = await connection.promise().query('INSERT INTO quizzes (title, description, creator_id) VALUES (?, ?, ?)', [title, description, userId]);
      const quizId = result.insertId;

      for (const question of questions) {
          const [questionResult] = await connection.promise().query('INSERT INTO questions (quiz_id, question_text) VALUES (?, ?)', [quizId, question.text]);
          const questionId = questionResult.insertId;

          for (const answer of question.answers) {
              await connection.promise().query('INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)', [questionId, answer.text, answer.is_correct]);
          }
      }

      res.json({ message: 'Quiz created successfully', quizId });
  } catch (error) {
      console.error('Error creating quiz:', error);
      res.status(500).json({ message: 'Error creating quiz' });
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

    const [questions] = await connection.promise().query(
      'SELECT COUNT(*) AS count FROM questions WHERE quiz_id = ?',
      [quizId]
    );

    const totalQuestions = questions[0].count;

    if (totalQuestions === 0) {
      return res.status(400).json({ message: 'No questions found for this quiz' });
    }

    const score = (correctCount / totalQuestions) * 100;

    await connection.promise().query(
      'INSERT INTO user_quizzes (user_id, quiz_id, score) VALUES (?, ?, ?)',
      [userId, quizId, score]
    );

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
      connection.query(query, [senderId, groupId, 'quiz', quizId], (err, results) => {
          if (err) {
              console.error('Error inserting message:', err);
              return res.status(500).send('Error sharing quiz');
          }
          res.status(200).send('Quiz shared successfully');
      });
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
      const sql = 'INSERT INTO events (title, date, user_id) VALUES (?, ?, ?)';
      connection.query(sql, [title, date, userId], (err, result) => {
          if (err) return res.status(500).send(err);
          res.send({ id: result.insertId });
      });
  } catch (error) {
      res.status(401).send(error.message);
  }
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

// Remove Event
app.post('/api/events/remove', (req, res) => {
  const { id, token } = req.body; // Assuming token-based authentication
  connection.query('DELETE FROM events WHERE id = ?', [id], err => {
      if (err) throw err;
      res.json({ success: true });
  });
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
      return res.status(401).json({ valid: false, message: 'Invalid token or session expired' });
    }


    // If the token is valid
    return res.status(200).json({ valid: true });
  });
});

// Route for the app download
app.get('/download/android', (req, res) => {
  const file = path.join(__dirname, 'public', 'app', 'Edusify.apk');
  res.download(file);
});

// Route for iOS download
app.get('/download/ios', (req, res) => {
  const file = path.join(__dirname, 'public', 'app', 'Educify.shortcut'); // Adjust path as necessary
  res.download(file);
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
const redirectUri = `${baseURL}/callback`; // Ensure this matches your Spotify Dashboard

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

      const uri = 'https://edusify.vercel.app/music';
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
    const sql = 'INSERT INTO eduscribes (content, user_id, image) VALUES (?, ?, ?)';
    connection.query(sql, [question, userId, imageName], (err, result) => {
      if (err) {
        console.error('Error executing query:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.status(200).json({ message: 'Eduscribe submitted successfully!', id: result.insertId });
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(401).json({ error: error.message });
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
  } catch (error) {
      console.error("Error generating content:", error);
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


// Route to update user avatar
app.put('/user/update/avatar', upload.single('avatar'), (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;

  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  getUserIdFromToken(token).then(userId => {
    if (!userId) {
      return res.status(400).send('User ID is missing');
    }

    const avatar = req.file ? req.file.filename : null;

    if (!avatar) {
      return res.status(400).send('No avatar file uploaded');
    }

    // Prepare the query to update avatar
    const query = `
      UPDATE users
      SET avatar = ?
      WHERE id = ?
    `;
    
    connection.query(query, [avatar, userId], (err, results) => {
      if (err) {
        console.error('Error updating avatar:', err);
        return res.status(500).send('Error updating avatar');
      }
      res.status(200).send('Avatar updated successfully');
    });
  }).catch(err => {
    console.error('Error fetching user ID:', err);
    res.status(500).send('Internal server error');
  });
});

// Route to update user profile details (excluding avatar)
app.put('/user/update', (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;

  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  getUserIdFromToken(token).then(userId => {
    if (!userId) {
      return res.status(400).send('User ID is missing');
    }

    const { unique_id, user_name, bio, location, phone_number } = req.body;

    // Prepare the query to update user details
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
app.post('/api/auth/forgot-password', (req, res) => {
  const { emailOrPhone } = req.body;
  connection.query('SELECT * FROM users WHERE email = ? OR phone_number = ?', [emailOrPhone, emailOrPhone], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = results[0];
    const token = generateToken();
    const resetLink = `https://edusify.vercel.app/reset-password/${token}`;

    // Store the token in the database
    connection.query('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)', [user.email, token, new Date(Date.now() + 3600000)], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      // Send email
      const mailOptions = {
        to: user.email,
        from: 'support@edusify.com',
        subject: 'Password Reset Request',
        html: `
          <p>Hi ${user.name || 'there'},</p>
          <p>We received a request to reset your password. Click the button below to reset your password:</p>
          <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #fff; background-color: #4CAF50; text-decoration: none; border-radius: 5px;">Reset Password</a>
          <p>If you didn't request this, please ignore this email.</p>
          <p>Best regards,<br>Your Edusify Team</p>
        `
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          console.log('Error sending email:', err);
          return res.status(500).json({ error: 'Error sending email' });
        }
        console.log('Email sent:', info.response);
        res.status(200).json({ message: 'Reset link sent' });
      });
    });
  });
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
            unit_amount: 60, // Amount in cents (e.g., $1.00)
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



// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

