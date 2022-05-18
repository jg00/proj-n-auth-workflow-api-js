// Eventually used in sendResetPasswordEmail.js, sendVerificationEmail.js

const nodemailer = require("nodemailer");
const nodemailerConfig = require("./nodemailerConfig");

const sendEmail = async ({ to, subject, html }) => {
  let testAccount = await nodemailer.createTestAccount();

  const transporter = nodemailer.createTransport(nodemailerConfig);

  return transporter.sendMail({
    from: '"Coding JG" <codingjg@gmail.com>', // from sender address
    to,
    subject,
    html,
  });
};

module.exports = sendEmail;
