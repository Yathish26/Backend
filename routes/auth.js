import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import { OAuth2Client } from 'google-auth-library';

const client = new OAuth2Client('515733859331-52g64ecis313qso8ejdtbjhlcbohnfg2.apps.googleusercontent.com');
const router = express.Router();

const JWT_SECRET = 'your_jwt_secret';

// Google Login
router.post('/google-login', async (req, res) => {
  const { token } = req.body; // The token sent from the client

  try {
    // Verify the token with Google
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: '515733859331-52g64ecis313qso8ejdtbjhlcbohnfg2.apps.googleusercontent.com', //  Google client ID
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;
    const profileImage = payload.picture;

    // Check if the user already exists in the database
    let user = await User.findOne({ email });
    if (!user) {
      // If user does not exist, create a new user
      user = new User({ name, email, password: 'google-auth-password', profileImage }); 
      await user.save();
    }

    const userPayload = { user: { id: user.id } };
    const jwtToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token: jwtToken });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

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
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

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
    res.json({
      name: user.name,
      email: user.email,
      bio: user.bio,
      businessName: user.businessName,
      description: user.description,
      workcategory: user.workcategory,
      location: user.location,
      phoneNumber: user.phoneNumber,
      profileImage: user.profileImage,
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

router.put('/user', auth, async (req, res) => {
  const { name, email, bio, businessName, description, workcategory, location, phoneNumber, profileImage } = req.body; // Extract fields to update

  try {
    const user = await User.findById(req.user.id); // Get the logged-in user

    // Update user fields if provided
    if (name) user.name = name;
    if (email) user.email = email;
    if (bio) user.bio = bio;
    if (businessName) user.businessName = businessName;
    if (description) user.description = description;
    if (workcategory) user.workcategory = workcategory;
    if (location) user.location = location;
    if (phoneNumber) user.phoneNumber = phoneNumber;
    if (profileImage) user.profileImage = profileImage;

    await user.save(); // Save updated user information
    res.json(user); // Return updated user data
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

export default router;
