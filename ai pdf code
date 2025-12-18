
app.post('/api/chat/ai', async (req, res) => {
  const { message, chatHistory, token, thinkingMode } = req.body; // Receive thinkingMode from frontend

  try {
    if (!message || typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    if (!token) {
      return res.status(400).json({ error: 'Token is required.' });
    }

    const userId = await getUserIdFromToken(token);
    if (!userId) {
      return res.status(401).json({ error: 'Invalid token or user not authenticated.' });
    }

    const modelName = thinkingMode ? "gemini-2.5-pro-exp-03-25" : "gemini-3-flash-preview"; // Toggle model

     // Fetch user data
     const userData = await Promise.all([
      query('SELECT title, due_date, description, created_at, priority FROM tasks WHERE user_id = ? AND completed = 1', [userId]),
      query('SELECT title, date FROM events WHERE user_id = ?', [userId]),
      query('SELECT study_plan FROM study_plans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [userId]),
      query('SELECT score, completed_at, quiz_id FROM user_quizzes WHERE user_id = ?', [userId]),
      query('SELECT title FROM quizzes WHERE id IN (SELECT quiz_id FROM user_quizzes WHERE user_id = ?)', [userId]),
      query('SELECT unique_id FROM users WHERE id = ?', [userId]),
      query('SELECT * FROM user_goal WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [userId]) // Fetch the latest user goal
    ]);

    // Extract user data
    const tasks = userData[0]; // Tasks
    const events = userData[1]; // Events
    const studyPlan = userData[2]?.[0]?.study_plan; // Latest Study Plan
    const quizResults = userData[3]; // Quiz Results
    const quizTitles = userData[4]; // Quiz Titles
    const userName = userData[5]?.[0]?.unique_id; // User's name (unique_id)
    const userGoal = userData[6]?.[0]; // Latest User Goal
    const today = new Date();
    const formattedDate = today.toISOString().split('T')[0]; // Format as YYYY-MM-DD
    // Build dynamic system instruction
    const dynamicSystemInstruction = `
      You are Edusify, an AI-powered productivity assistant designed to help students manage their academic tasks, study materials, and stay organized. Your mission is to provide tailored assistance and streamline the study experience with a wide range of features.

      Here is the information about the user:
      - **Name**: ${userName || 'Unknown'}
      - **Tasks**: ${tasks.length > 0 ? tasks.map(task => `- ${task.title} (Due: ${task.due_date}, Priority: ${task.priority})`).join('\n') : 'No tasks available.'}
      - **Events**: ${events.length > 0 ? events.map(event => `- ${event.title} (Date: ${event.date})`).join('\n') : 'No upcoming events.'}
      - **Study Plan**: ${studyPlan || 'No study plan available.'}
      - **Quiz Results**: ${quizResults.length > 0 ? quizResults.map((result, index) => {
        const quizTitle = quizTitles[index]?.title || 'Unknown Quiz';
        return `- ${quizTitle}: Score: ${result.score}, Completed on: ${result.completed_at}`;
      }).join('\n') : 'No quiz results available.'}
       - **User Goal**: ${userGoal ? `
        - **Grade**: ${userGoal.grade || 'N/A'}
        - **Goal**: ${userGoal.goal || 'N/A'}
        - **Study Time**: ${userGoal.study_time || 'N/A'}
        - **Speed**: ${userGoal.speed || 'N/A'}
        - **Revision Method**: ${userGoal.revision_method || 'N/A'}
        - **Pomodoro Preference**: ${userGoal.pomodoro_preference || 'N/A'}
        - **Subjects**: ${userGoal.subjects || 'N/A'}
        - **Recent Grades**: ${userGoal.recent_grades || 'N/A'}
        - **Exam Details**: ${userGoal.exam_details || 'N/A'}
        - **Daily Routine**: ${userGoal.daily_routine || 'N/A'}
      ` : 'No user goal available.'}
- **Today's Date**: ${formattedDate}
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
   
  ### **AI Guidelines & Limitations:**
  - **AI does not directly edit** schedules, study plans, to-do lists, or quizzes. Users must make changes manually.
  - **AI provides guidance only**—it suggests improvements, structures plans, and offers recommendations.
  - **AI does not set reminders**—users must manage them manually.
  - **AI instantly generates summaries** without excessive questions. If refinements are needed, it waits for feedback.
  - **AI subtly encourages Premium features** without aggressive promotion.
  
  "When responding to user requests related to schedules, tasks, or notes, generate a general plan or summary based on the provided input without asking for too many details. If the user provides a broad topic, generate a summary note instead of requesting more specifics. If the user requires changes, wait for their feedback and adjust accordingly. Keep the flow of conversation smooth and focused on providing immediate value, not excessive clarifications."
    `;


    const model = genAI.getGenerativeModel({
      model: modelName,
      safetySettings: safetySettings,
      systemInstruction: dynamicSystemInstruction
    });

    const initialChatHistory = [
      { role: 'user', parts: [{ text: 'Hello' }] },
      { role: 'model', parts: [{ text: 'Great to meet you. What would you like to know?' }] },
    ];

    const chat = model.startChat({ history: chatHistory || initialChatHistory });

    console.log(`User asked: ${message}, User ID: ${userId}, Thinking Mode: ${thinkingMode}`);

    let aiResponse = '';

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const result = await chat.sendMessage(message);
        aiResponse = result.response?.text?.() || 'No response from AI.';
        console.log(`AI responded on attempt ${attempt}`);
        break;
      } catch (error) {
        console.error(`Attempt ${attempt} failed:`, error.message);

        if (attempt === MAX_RETRIES) {
          throw new Error('AI service failed after multiple attempts.');
        }

        const delayMs = Math.pow(2, attempt) * 100;
        console.log(`Retrying in ${delayMs}ms...`);
        await delay(delayMs);
      }
    }

    if (!aiResponse || aiResponse === 'No response from AI.') {
      return res.status(500).json({ error: 'AI service did not return a response.' });
    }

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








app.post('/api/chat/ai', uploadPDF.single('pdf'), async (req, res) => {
    try {
      const { message, chatHistory, token } = req.body;
  
      // Validate inputs
      if (!message || !token) {
        return res.status(400).json({ error: 'Message and token are required.' });
      }
  
      // Get user ID from token
      const userId = await getUserIdFromToken(token);
      if (!userId) {
        return res.status(401).json({ error: 'Invalid token or user not authenticated.' });
      }
  
      let parsedChatHistory = [];
      if (chatHistory) {
        try {
          parsedChatHistory = JSON.parse(chatHistory);
        } catch (e) {
          return res.status(400).json({ error: 'Invalid chat history format.' });
        }
      }
  
      // Ensure chat history starts with a valid 'user' role
      if (!parsedChatHistory.length || parsedChatHistory[0].role !== 'user') {
        return res.status(400).json({ error: 'Chat history must start with role "user".' });
      }
  
      let pdfText = '';
      let pdfError = false;
  
      if (req.file) {
        // Extract text from the uploaded PDF
        const pdfPath = req.file.path;
        try {
          pdfText = await pdfParse(fs.readFileSync(pdfPath)).then((data) => data.text);
          if (!pdfText) {
            console.log(`User ID: ${userId} - Unable to extract text from PDF.`);
            pdfError = true; // Indicate PDF could not be read
          }
        } catch (error) {
          console.error(`Error extracting text from PDF for User ID: ${userId}:`, error);
          pdfError = true; // Indicate PDF could not be read
        }
      }
  
      // Combine PDF text with the user message
      const finalMessage = pdfText ? `${pdfText}\n\n${message}` : message;
  
      // Log the type of message
      console.log(
        `User ID: ${userId}, Message Type: ${req.file ? 'With PDF' : 'Just Message'}, Message: ${message}`
      );
  
      // Start a new chat session
      const chat = model.startChat({
        history: parsedChatHistory,
      });
  
      // Send the message to the AI model
      const result = await chat.sendMessage(finalMessage);
      let aiResponse = result.response.text();
  
      // Append a note about PDF reading issues if applicable
      if (pdfError) {
        aiResponse += ' (PDF could not be read)';
      }
  
      // Log success and AI's response
      console.log(`AI Response for User ID: ${userId} - Success`);
      console.log(`AI Responded `);
  
      // Save the interaction in the database
      await query(
        'INSERT INTO ai_history (user_id, user_message, ai_response) VALUES (?, ?, ?)',
        [userId, message, aiResponse]
      );
  
      // Send the AI response back to the client
      res.json({ response: aiResponse });
    } catch (error) {
      console.error('Error in /api/chat/ai endpoint:', error);
      res.status(500).json({
        error: 'An error occurred while processing your request. Please try again later.',
      });
    }
  });
  