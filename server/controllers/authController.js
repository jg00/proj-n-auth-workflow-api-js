const User = require("../models/User");
const Token = require("../models/Token");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");
const {
  attachCookiesToResponse,
  createTokenUser,
  sendVerificationEmail,
  sendResetPasswordEmail,
  createHash,
} = require("../utils");
const crypto = require("crypto");

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError("Email already exists");
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? "admin" : "user";

  const verificationToken = crypto.randomBytes(40).toString("hex"); // Buffer convert each Byte encoded to two 'hex' characters (default utf-8)

  const user = await User.create({
    name,
    email,
    password,
    role,
    verificationToken,
  });

  const origin = "http://localhost:3000"; // For production we would replace

  // __When working with proxies__
  // console.log(req); // We could also construct the origin using req object headers (ex: headers: {'x-forwarded-host':'localhost:3000'})

  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });

  // Send verification token back only while testing in postman!
  res.status(StatusCodes.CREATED).json({
    msg: "Success! Please check your email to verify account",
  });
};

/* Reference - req object
  const tempOrigin = req.get("origin");
  console.log(`origin : ${tempOrigin}`);

  const protocol = req.protocol;
  console.log(`protocol : ${protocol}`);

  const host = req.get("host");
  console.log(`host : ${host}`);

  const forwardedHost = req.get("x-forwarded-host");
  console.log(`forwardedHost : ${forwardedHost}`);

  const forwardedProtocol = req.get("x-forwarded-proto");
  console.log(`forwardedProtocol : ${forwardedProtocol}`);
*/

// Eventually this will be sent from our frontend when user clicks verify link from their email.
const verifyEmail = async (req, res) => {
  const { email, verificationToken } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError("Verification Failed");
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError("Verification Failed");
  }

  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = ""; // Now subsequent request to verify email will no longer work.  One time verification.

  await user.save();

  res.status(StatusCodes.OK).json({ msg: "Email Verified" });
};

// Approach - return accessToken (shorter expiration), refreshToken
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError("Please provide email and password");
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError("Invalid Credentials");
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError("Invalid Credentials");
  }

  // Register workflow - requires user validated their email
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError("Please verify your email");
  }

  // __AccessToken__
  const tokenUser = createTokenUser(user); // ex: jwt payload - {name, userId, role}

  // __RefreshToken__
  // Create or use existing refresh token associated to a user
  let refreshToken = "";

  // When user attempts to log in check for existing token in db
  const existingToken = await Token.findOne({ user: user._id });

  if (existingToken) {
    const { isValid } = existingToken; // As admins we can change in backend to false manually to revoke access immediately
    if (!isValid) {
      throw new CustomError.UnauthenticatedError("Invalid Credentials");
    }
    refreshToken = existingToken.refreshToken; // Reuse existing
    attachCookiesToResponse({ res, user: tokenUser, refreshToken }); // Note cookie expiration will be used
    res.status(StatusCodes.OK).json({ user: tokenUser });
    return;
  }

  // If user authenticated above but no existing refreshToken create one and save to db
  refreshToken = crypto.randomBytes(40).toString("hex"); // ex: "50bbaacc.."
  const userAgent = req.headers["user-agent"];
  const ip = req.ip;
  const userToken = { refreshToken, ip, userAgent, user: user._id };

  await Token.create(userToken); // Token tied to a user and persist to db

  attachCookiesToResponse({ res, user: tokenUser, refreshToken }); // Step creates JWT token and attaches to cookies
  res.status(StatusCodes.OK).json({ user: tokenUser });
};

const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });

  res.cookie("accessToken", "logout", {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.cookie("refreshToken", "logout", {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(StatusCodes.OK).json({ msg: "user logged out!" });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError.BadRequestError("Please provide valid email");
  }

  const user = await User.findOne({ email });

  if (user) {
    const passwordToken = crypto.randomBytes(70).toString("hex");

    // send email
    const origin = "http://localhost:3000"; // For production we would replace

    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin,
    });

    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = createHash(passwordToken); // Save hashed
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  // Regardless if user with email found we still send message below
  res
    .status(StatusCodes.OK)
    .json({ msg: "Please check your email for reset password link" });
};

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;

  if (!token || !email || !password) {
    throw new CustomError.BadRequestError("Please provide all values");
  }

  const user = await User.findOne({ email });

  if (user) {
    const currentDate = new Date();

    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }

  res.send("resetPassword");
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
