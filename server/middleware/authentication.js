const CustomError = require("../errors");
const { isTokenValid } = require("../utils");
const Token = require("../models/Token");
const { attachCookiesToResponse } = require("../utils");

const authenticateUser = async (req, res, next) => {
  const { refreshToken, accessToken } = req.signedCookies;
  // accessToken - shorter cookie expiration

  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken);
      req.user = payload.user;
      return next();
    }

    const payload = isTokenValid(refreshToken); // Note both userToken and refreshToken string passed in during login

    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken: payload.refreshToken,
    });

    if (!existingToken || !existingToken?.isValid) {
      throw new CustomError.UnauthenticatedError("Authentication Invalid");
    }

    // Always sends back accessToken and refreshToken cookies with updated expiration date/times.
    attachCookiesToResponse({
      res,
      user: payload.user,
      refreshToken: existingToken.refreshToken,
    });

    req.user = payload.user;
    next();
  } catch (error) {
    throw new CustomError.UnauthenticatedError("Authentication Invalid");
  }
};

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new CustomError.UnauthorizedError(
        "Unauthorized to access this route"
      );
    }
    next();
  };
};

module.exports = {
  authenticateUser,
  authorizePermissions,
};

/* Before refactor to check two tokens
  const authenticateUser = async (req, res, next) => {
    const token = req.signedCookies.token;

    if (!token) {
      throw new CustomError.UnauthenticatedError('Authentication Invalid');
    }

    try {
      const { name, userId, role } = isTokenValid({ token });
      req.user = { name, userId, role };
      next();
    } catch (error) {
      throw new CustomError.UnauthenticatedError('Authentication Invalid');
    }
  };
*/
