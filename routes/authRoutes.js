const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const send2FACode = require('../utils/email');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// 📧 Sends security alert after 5 failed login attempts
const sendSecurityAlertEmail = async (email) => {
  try {
    await transporter.sendMail({
      from: `"Secure Password Manager" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Security Alert: Failed Login Attempts',
      text: `We've detected 5 failed login attempts on your account. If this wasn't you, please consider changing your password or contacting support.`,
    });
  } catch (err) {
    console.error('Failed to send security alert email:', err);
  }
};

// 🧾 Register a new user
router.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({ email, passwordHash });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Registration failed' });
  }
});

// 🔐 Login + 2FA + failed login alert
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    if (user.isSuspended) {
      return res.status(403).json({ message: 'Account suspended' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      if (user.loginAttempts >= 5) {
        await sendSecurityAlertEmail(user.email);
        user.loginAttempts = 0; // reset after alert
      }

      await user.save();
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Reset failed attempts
    user.loginAttempts = 0;

    // Generate 6-digit 2FA code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.twoFactorCode = code;
    user.twoFactorExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    await user.save();
    await send2FACode(user.email, code);

    res.json({ message: '2FA code sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Login failed' });
  }
});

// ✅ 2FA verification
router.post('/verify-2fa', async (req, res) => {
  const { email, code } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    if (
      user.twoFactorCode !== code ||
      !user.twoFactorExpires ||
      new Date() > user.twoFactorExpires
    ) {
      return res.status(401).json({ message: 'Invalid or expired 2FA code' });
    }

    user.twoFactorCode = null;
    user.twoFactorExpires = null;
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 🔒 Change password
const authMiddleware = require('../middleware/auth');
router.post('/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect current password' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(newPassword, salt);

    user.passwordHash = hashed;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ message: 'Failed to update password' });
  }
});

// 🔁 Forgot password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'If this email is registered, a reset link will be sent.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetTokenExpires = Date.now() + 15 * 60 * 1000;
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      from: `"Secure Password Manager" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Reset Your Password',
      text: `Click this link to reset your password: ${resetUrl}\nThis link is valid for 15 minutes.`,
    });

    res.json({ message: 'If this email is registered, a reset link will be sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ message: 'Something went wrong. Try again.' });
  }
});

// 🔓 Verify reset token and issue JWT
router.post('/verify-reset-token', async (req, res) => {
  const { token } = req.body;

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired link.' });
    }
     res.json({ message: 'Token is valid.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Something went wrong.' });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }
    });
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }
    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    user.resetToken = null;
    user.resetTokenExpires = null;
    await user.save();
    res.json({ message: 'Password updated! You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Something went wrong.' });
  }
});

module.exports = router;
