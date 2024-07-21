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
const nodemailer = require('nodemailer');

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
    email
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
            'INSERT INTO users (phone_number, password, user_name, email) VALUES (?, ?, ?, ?)';
          const values = [
            phone,
            hash,
            username,
            email
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

// Route to end the current event
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: 'dropmentset@gmail.com',
      pass: 'pgpq ydgd qztt mcex',
  },
});

app.post("/login", (req, res) => {
  const phone = req.body.phone;
  const password = req.body.password;

  connection.query(
      "SELECT * FROM users WHERE phone_number = ?",
      [phone],
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

                              // Send OTP via Email
                              const mailOptions = {
                                  from: 'dropmentset@gmail.com',
                                  to: result[0].email, // Ensure the user table has an email column
                                  subject: 'Your OTP for Login',
                                  text: `Your OTP for login is ${otp}`
                              };

                              transporter.sendMail(mailOptions, (err, info) => {
                                  if (err) {
                                      console.log(err);
                                  } else {
                                      console.log('Email sent: ' + info.response);
                                  }
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




// Check tasks and events, and send reminders
const checkTasksAndSendReminders = () => {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const tomorrow = new Date(new Date().setDate(new Date().getDate() + 1)).toISOString().split('T')[0];
  const dayAfter = new Date(new Date().setDate(new Date().getDate() + 2)).toISOString().split('T')[0];

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

  connection.query(tasksQuery, [today, tomorrow, dayAfter], (err, taskResults) => {
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

          let messageBody = `Reminder: Your task "${title}" is due on ${formattedDate}.`;

          // Send email
          const mailOptions = {
              from: 'dropmentset@gmail.com',
              to: email,
              subject: 'Task Reminder',
              text: messageBody
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

  connection.query(eventsQuery, [today, tomorrow, dayAfter], (err, eventResults) => {
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

          let messageBody = `Reminder: Your event "${title}" is scheduled for ${formattedDate}.`;

          // Send email
          const mailOptions = {
              from: 'dropmentset@gmail.com',
              to: email,
              subject: 'Event Reminder',
              text: messageBody
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

// Run the task-checking function every 24 hours
setInterval(checkTasksAndSendReminders, 86400000); // 24 hours in milliseconds

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
  const query = `SELECT * FROM \`groups\` WHERE id = ?`; // Escaped table name
  connection.query(query, [groupId], (err, results) => {
      if (err) throw err;
      const group = results[0];
      const messagesQuery = `SELECT * FROM \`messages\` WHERE group_id = ?`; // Escaped table name
      connection.query(messagesQuery, [groupId], (err, messages) => {
          if (err) throw err;
          res.json({ ...group, messages });
      });
  });
});


app.post('/api/groups/messages/send/:id', async (req, res) => {
  const groupId = req.params.id;
  const { content, type, sender } = req.body;
  const token = req.headers.authorization.split(' ')[1]; // Extract token from header

  try {
    const userId = await getUserIdFromToken(token);
      const query = `INSERT INTO messages (group_id, content, sender, type) VALUES (?, ?, ?, ?)`;
      connection.query(query, [groupId, content, userId, type], (err, results) => {
          if (err) {
              console.error('Error inserting message:', err);
              res.sendStatus(500);
          } else {
              res.sendStatus(200);
          }
      });
  } catch (error) {
      console.error('Error fetching user ID:', error);
      res.sendStatus(401); // Unauthorized
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
      connection.query('SELECT user_name FROM users WHERE id = ?', [user_id], (err, results) => {
          if (err) {
              console.error('Error fetching user_name:', err);
              return res.status(500).send('Failed to fetch user name.');
          }

          if (results.length === 0) {
              return res.status(404).send('User not found.');
          }

          res.json({ user_name: results[0].user_name });
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
          SELECT id, user_name
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


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

