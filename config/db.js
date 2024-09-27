// config/db.js
import mongoose from 'mongoose';
dotenv.config();

const dbURI = process.env.MONGODB_URI;


const connectDB = async () => {
  try {
    await mongoose.connect(dbURI); 
    console.log('MongoDB connected');
  } catch (err) {
    console.error('Error connecting to MongoDB', err.message);
    process.exit(1);
  }
};

export default connectDB;
