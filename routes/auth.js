const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const User = require('../models/User');
const PasswordReset = require('../models/PasswordReset');

// Login page
router.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('auth/login', { title: 'Login' });
});

// Login process
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.render('auth/login', {
        title: 'Login',
        error: 'Email atau password salah'
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.render('auth/login', {
        title: 'Login',
        error: 'Email atau password salah'
      });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address,
      role: user.role
    };

    if (user.role === 'admin') {
      res.redirect('/admin/dashboard');
    } else {
      res.redirect('/');
    }
  } catch (error) {
    console.error(error);
    res.render('auth/login', {
      title: 'Login',
      error: 'Terjadi kesalahan sistem'
    });
  }
});

// Register page
router.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('auth/register', { title: 'Register' });
});

// Register process
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, phone, address } = req.body;

    // Check if email exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.render('auth/register', {
        title: 'Register',
        error: 'Email sudah terdaftar'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      phone,
      address
    });

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address,
      role: user.role
    };

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.render('auth/register', {
      title: 'Register',
      error: 'Terjadi kesalahan sistem'
    });
  }
});

// Logout
router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Forgot password page
router.get('/forgot-password', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('auth/forgot-password', { title: 'Forgot Password' });
});

// Send OTP for forgot password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email, otp: otpFromClient } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.render('auth/forgot-password', {
        title: 'Forgot Password',
        error: 'Email tidak terdaftar'
      });
    }

    // Use OTP from client if provided, otherwise generate a new one
    const otp = otpFromClient || Math.floor(1000 + Math.random() * 9000).toString();

    // Set expiry 10 minutes from now
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // Save OTP to database
    await PasswordReset.create({
      email,
      otp,
      expires_at: expiresAt
    });

    res.render('auth/forgot-password', {
      title: 'Forgot Password',
      success: 'OTP telah dikirim ke email Anda',
      email
    });
  } catch (error) {
    console.error(error);
    res.render('auth/forgot-password', {
      title: 'Forgot Password',
      error: 'Terjadi kesalahan sistem'
    });
  }
});

// Verify OTP page
router.get('/verify-otp', (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.redirect('/auth/forgot-password');
  }
  res.render('auth/verify-otp', { title: 'Verify OTP', email });
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const resetRecord = await PasswordReset.findOne({
      where: {
        email,
        otp,
        used: false
      },
      order: [['created_at', 'DESC']]
    });

    if (!resetRecord || resetRecord.expires_at < new Date()) {
      return res.render('auth/verify-otp', {
        title: 'Verify OTP',
        email,
        error: 'OTP tidak valid atau sudah kadaluarsa'
      });
    }

    // Mark as used
    resetRecord.used = true;
    await resetRecord.save();

    res.render('auth/reset-password', {
      title: 'Reset Password',
      email
    });
  } catch (error) {
    console.error(error);
    res.render('auth/verify-otp', {
      title: 'Verify OTP',
      email,
      error: 'Terjadi kesalahan sistem'
    });
  }
});

// Reset password
router.post('/reset-password', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.render('auth/reset-password', {
        title: 'Reset Password',
        email,
        error: 'Password tidak cocok'
      });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.redirect('/auth/login');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);
    user.password = hashedPassword;
    await user.save();

    res.render('auth/login', {
      title: 'Login',
      success: 'Password berhasil direset. Silakan login.'
    });
  } catch (error) {
    console.error(error);
    res.render('auth/reset-password', {
      title: 'Reset Password',
      email,
      error: 'Terjadi kesalahan sistem'
    });
  }
});

module.exports = router;