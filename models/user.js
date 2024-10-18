// models/User.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    maxlength: 50,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  bio: {
    type: String,
    default: '',
  },
  businessName: {
    type: String,
    default: '',
  },
  description: {
    type: String,
    default: '',
  },
  workcategory: {
    type: String,
    default: '',
  },
  location: {
    type: String,
    default: '',
  },
  phoneNumber: {
    type: String,
    default: '',
  },
  profileImage: {
    type: String,
  }
});

// Pre-save hook to hash passwords before saving to DB
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', UserSchema);

export default User;

