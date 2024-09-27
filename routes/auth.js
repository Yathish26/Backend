import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';
const router = express.Router();

const JWT_SECRET = 'your_jwt_secret';

// Middleware to authenticate token
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Register User
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    user = new User({ name, email, password });
    await user.save();

    const payload = { user: { id: user.id } };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Login User
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    const payload = { user: { id: user.id } };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get User Details
router.get('/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }
    res.json({ name: user.name, email: user.email, bio: user.bio, businessName: user.businessName, description: user.description, phoneNumber: user.phoneNumber });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

router.put('/user', auth, async (req, res) => {
  const { name, email, bio, businessName, description, workcategory, phoneNumber } = req.body; // Extract fields to update

  try {
    const user = await User.findById(req.user.id); // Get the logged-in user

    // Update user fields if provided
    if (name) user.name = name;
    if (email) user.email = email;
    if (bio) user.bio = bio;
    if (businessName) user.businessName = businessName;
    if (description) user.description = description;
    if (workcategory) user.workcategory = workcategory
    if (phoneNumber) user.phoneNumber = phoneNumber;

    await user.save(); // Save updated user information
    res.json(user); // Return updated user data
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

export default router;
