// server.js
import express from 'express';
import connectDB from './config/db.js';
import authRoutes from './routes/auth.js'; // Import the auth routes
import cors from 'cors'

const app = express();

// Connect to MongoDB
connectDB();

// Middleware for JSON parsing
app.use(express.json());

app.use(cors());
//

// app.use(cors({
//     origin: 'https://hirearrive.vercel.app',
//     credentials: true
// }));

// Sample Route (for testing server)
app.get('/', (req, res) => res.send('API is running'));

// Routes
app.use('/api/auth', authRoutes); // Use the imported routes

// Define a PORT and start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
