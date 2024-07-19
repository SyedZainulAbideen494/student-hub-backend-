const express = require("express");
const mysql = require("mysql2");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const PORT = process.env.PORT || 8080;
const axios = require('axios');
const cheerio = require('cheerio');
const querystring = require('querystring'); // Include the querystring module

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
  origin: "*",
  methods: ["GET", "POST", "DELETE", "PUT"],
  credentials: true,
}));

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



// GET endpoint for testing
app.get('/', (req, res) => {
  res.send('Welcome!');
});



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


app.post('/signup', (req, res) => {
  const {
    phone,
    password,
    username,
  } = req.body;

 
  // Check if the email already exists in the database
  const checkEmailQuery = 'SELECT * FROM users WHERE phone_number = ?';
  connection.query(checkEmailQuery, [phone], (err, results) => {
    if (err) {
      console.error('Error checking phone number:', err);
      res.status(500).json({ error: 'Internal server error' });
    } else if (results.length > 0) {
      // If email already exists, return a message
      res.status(409).json({ error: 'User with this email already exists' });
    } else {
      // If email doesn't exist, proceed with user registration
      bcrypt.hash(password, saltRounds, (hashErr, hash) => {
        if (hashErr) {
          console.error('Error hashing password: ', hashErr);
          res.status(500).json({ error: 'Internal server error' });
        } else {
          const insertQuery =
            'INSERT INTO users (phone_number, password, user_name) VALUES (?, ?, ?)';
          const values = [
            phone,
            hash,
            username
          ];

          connection.query(insertQuery, values, (insertErr, insertResults) => {
            if (insertErr) {
              console.error('Error inserting user: ', insertErr);
              res.status(500).json({ error: 'Internal server error' });
            } else {
              console.log('User registration successful!');
              res.sendStatus(200);
            }
          });
        }
      });
    }
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

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});


function generateOTP() {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < 6; i++) {
      otp += digits[Math.floor(Math.random() * 10)];
  }
  return otp;
}

app.post("/login", (req, res) => {
  const phone = req.body.phone;
  const password = req.body.password;

  connection.query(
      "SELECT * FROM users WHERE phone_number = ?",
      phone,
      (err, result) => {
          if (err) {
              return res.send({ err: err });
          }
          if (result.length > 0) {
              bcrypt.compare(password, result[0].password, (error, response) => {
                  if (response) {
                      // Generate OTP and save in database
                      const otp = generateOTP();
                      connection.query(
                          "INSERT INTO 2fa (phone_number, otp) VALUES (?, ?)",
                          [phone, otp],
                          (err, otpResult) => {
                              if (err) {
                                  console.log(err);
                                  return res.status(500).send({ message: "Error generating OTP" });
                              }
                             
                              // Send OTP via WhatsApp (or SMS)
                              sendWhatsAppMessage({
                                messaging_product: "whatsapp",
                                to: `91${phone}`,
                                type: "text",
                                text: { body: `Your OTP for login is ${otp}` }
                              });

                              res.json({ auth: true, message: "OTP sent for verification" });
                          }
                      );
                  } else {
                      res.json({ auth: false, message: "Phone number or password is wrong" });
                  }
              });
          } else {
              res.json({ auth: false, message: "User does not exist" });
          }
      }
  );
});


app.post("/verify-otp", (req, res) => {
  const phone = req.body.phone;
  const otp = req.body.otp;

  // Verify the OTP
  connection.query(
      "SELECT * FROM 2fa WHERE phone_number = ? AND otp = ? AND active = 1 AND created_at >= NOW() - INTERVAL 2 MINUTE",
      [phone, otp],
      (err, result) => {
          if (err) {
              console.error("Database error while verifying OTP:", err);
              return res.status(500).send({ message: "Database error while verifying OTP" });
          }

          if (result.length > 0) {
              // OTP is valid, now fetch user details
              connection.query(
                  "SELECT * FROM users WHERE phone_number = ?",
                  [phone],
                  (userErr, userResult) => {
                      if (userErr) {
                          console.error("Database error while fetching user details:", userErr);
                          return res.status(500).send({ message: "Database error while fetching user details" });
                      }

                      if (userResult.length > 0) {
                          const userId = userResult[0].id;

                          // Update OTP status to inactive
                          connection.query(
                              "UPDATE 2fa SET active = 0 WHERE phone_number = ? AND otp = ?",
                              [phone, otp],
                              (updateErr, updateResult) => {
                                  if (updateErr) {
                                      console.error("Error updating OTP status:", updateErr);
                                      return res.status(500).send({ message: "Error updating OTP status" });
                                  }

                                  // Proceed with login if OTP is verified
                                  const token = jwt.sign({ id: userId }, "jwtsecret", {
                                      expiresIn: 86400, // 24 hours
                                  });

                                  // Create a session for the user
                                  connection.query(
                                      "INSERT INTO session (user_id, jwt) VALUES (?, ?)",
                                      [userId, token],
                                      (sessionErr, sessionResult) => {
                                          if (sessionErr) {
                                              console.error("Error creating session:", sessionErr);
                                              return res.status(500).send({ message: "Error creating session" });
                                          }

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

app.post('/add/tasks', (req, res) => {
  const { title, description, due_date, priority, token } = req.body;

  const getUserQuery = 'SELECT user_id FROM session WHERE jwt = ?';
  connection.query(getUserQuery, [token], (err, results) => {
      if (err) {
          return res.status(500).send(err);
      }
      if (results.length === 0) {
          return res.status(404).send({ message: 'User not found' });
      }

      const user_id = results[0].user_id;
      const insertQuery = 'INSERT INTO tasks (title, description, due_date, priority, user_id) VALUES (?, ?, ?, ?, ?)';
      connection.query(insertQuery, [title, description, due_date, priority, user_id], (err, results) => {
          if (err) {
              return res.status(500).send(err);
          }
          res.status(201).send({ id: results.insertId });
      });
  });
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

// Check tasks and send reminders
const checkTasksAndSendReminders = () => {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const tomorrow = new Date(new Date().setDate(new Date().getDate() + 1)).toISOString().split('T')[0];
  const dayAfter = new Date(new Date().setDate(new Date().getDate() + 2)).toISOString().split('T')[0];

  // Query to get tasks due today, tomorrow, or day after
  const query = `
    SELECT t.title, t.due_date, u.phone_number 
    FROM tasks t
    JOIN users u ON t.user_id = u.id
    WHERE t.due_date IN (?, ?, ?)
  `;

  connection.query(query, [today, tomorrow, dayAfter], (err, results) => {
    if (err) {
      console.error('Error fetching tasks:', err);
      return;
    }

    results.forEach(task => {
      const { phone_number, title, due_date } = task;
      const formattedDate = new Date(due_date).toLocaleDateString('en-IN', { 
        day: '2-digit', 
        month: '2-digit', 
        year: 'numeric' 
      });
      
      let messageBody = `Reminder: Your task "${title}" is due on ${formattedDate}.`;
      
      sendWhatsAppMessage({
        messaging_product: "whatsapp",
        to: `91${phone_number}`, // Add country code
        type: "text",
        text: { body: messageBody }
      });
    });
  });
};

// Run the task-checking function every 24 hours
setInterval(checkTasksAndSendReminders, 86400000); // 24 hours in milliseconds
// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

