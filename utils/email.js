const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const send2FACode = (to, code) => {
  return transporter.sendMail({
    from: `"Secure Password Manager" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Your 2FA Code',
    text: `Your code is: ${code}`,
  });
};

module.exports = send2FACode;
