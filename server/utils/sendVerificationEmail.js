// Used in authController register
const sendEmail = require("./sendEmail");

// Return sendEmail function from this function
const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const verifyEmail = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  const message = `<p>Please confirm your email by clicking on the following link : 
  <a href="${verifyEmail}">Verify Email</a><p>`;

  return sendEmail({
    to: email,
    subject: "Email Confirmation",
    html: `<h4> Hello ${name}</h4>
    ${message}`,
  });
};

module.exports = sendVerificationEmail;

/*
  origin - url for our frontend - either localhost or production
*/
