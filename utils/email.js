const SibAPIv3Sdk = require("sib-api-v3-sdk");

const client = SibAPIv3Sdk.ApiClient.instance;
const apiKey = client.authentications["api-key"];
apiKey.apiKey = process.env.BREVO_API_KEY;


const emailApi = new SibAPIv3Sdk.TransactionalEmailsApi();


const sendEmail = async({to, subject, text, html})=> {
  try{
    await emailApi.sendTransacEmail({
      sender:{
        email:process.env.EMAIL_SENDER,
        name:"Secure Password Manager"
      },
      to: [{email: to}],
      subject,
      textContent: text,
      htmlContent: html,
      logger: true
    })
    console.log(`Email send to ${to}`)
  }
  catch(error){
    console.error("Brevo email error:", error);
    throw error;
  }
};

// 2FA
const send2FACode = async (to, code) => {
  return sendEmail({
    to,
    subject: `Your 2FA Code`,
    text: `Your code is: ${code}`,
    html: `<h2>Your 2FA Code</h2><p>Your code is: <b>${code}</b></p>`,
  });
};


// Security alert
const sendSecurityAlertEmail = async (to) => {
  return sendEmail({
    to,
    subject: `Security Alert: Failed Login Attempts`,
    text: `We've detected 5 failed login attempts on your account. If this wasn't you, please consider changing your password or contacting support.`,
    html: `<h2>Security Alert</h2><p>Multiple failed login attempts detected.</p> <p>We've detected 5 failed login attempts on your account. If this wasn't you, please consider changing your password or contacting support.</p>`,
  });
};


// Reset password
const sendResetPasswordEmail = async (to, resetUrl) => {
  return sendEmail({
    to,
    subject: `Reset Your Password`,
    text: `Click this link to reset your password: ${resetUrl}\nThis link is valid for 15 minutes.`,
    html: `<h2>Password Reset</h2><p>Click this link to reset your password: <a href="${resetUrl}">Reset Your Password</a></p> <p>This link is valid for 15 minutes.</p>`,
  });
};


module.exports = {
  send2FACode,
  sendSecurityAlertEmail,
  sendResetPasswordEmail,
};
/* const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 587,
  secure: false, 
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  logger: true,    // покаже лог на консоль
  debug: true, 
});

const send2FACode = async (to, code) => {
  try {
    await transporter.sendMail({
      from: `${process.env.EMAIL_USER}`,
      to,
      subject: "Your 2FA Code",
      text: `Your code is: ${code}`,
     
    });
    console.log(`2FA code sent to ${to}`);
  } catch (err) {
    console.error(`Error sending 2FA code to ${to}:`, err);
  }
};
module.exports = send2FACode;
*/
