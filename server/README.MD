## Auth Workflow

Auth Workflow backend project. Register, login, verify email, refresh token, reset password.

<img width="326" alt="auth-workflow" src="https://user-images.githubusercontent.com/43181662/169139368-66d50389-55cd-4729-b83d-12f32978c564.png">

## Technologies

:coffee: **_Node_**

:coffee: **_Express_**

#### Update User Model

- [] add following three properties
- [] verificationToken - String
- [] isVerified - {type:Boolean, default:false}
- [] verified - Date

#### Update Register Controller

- [] setup fake verificationToken - 'fake token'
- [] remove everything after User.create()
- [] send back success message and token

#### Update Login Controller

- [] right after isPasswordCorrect
- [] check if user.isVerified, if not 401

#### Verify Email Controller

- [] create verifyEmail in authController
- [] get verificationToken and email from req.body
- [] setup a '/verify-email' route in authRoutes
- [] test in a Postman
- [] check for user using email
- [] if no user 401
- [] if token does not match user token 401
- [] if correct set
- [] user.isVerified = true
- [] user.verified = Date.now()
- [] user.verificationToken = ''
- [] save use with instance method
- [] return msg:'email verified'

#### Email Setup

- [] re-watch project 08
- [] ethereal credentials (create account/login)
- [] install nodemailer
- [] create (nodemailerConfig, sendEmail,
  sendResetPasswordEmail, sendVerficationEmail) files in utils

#### Send Verification Link

- [] refactor sendEmail
- [] setup sendVerificationEmail.js
- [] pass arguments

#### Token Model

- [] create Token.js in models
- [] refreshToken,ip,userAgent - all String and required
- [] isValid - Boolean, default:true
- [] ref user
- [] timestamps true

#### Setup Token in Login Controller

#### Send Multiple Cookies

#### Check for Existing Token

#### Refactor Auth Middleware - Access , Refresh Token

#### Logout

#### Forgot/Reset Password Functionality

- User Model
- passwordToken {type:String}
- passwordTokenExpirationDate {type:Date}
- authController
- forgotPassword and resetPassword
- authRoutes
- post '/forgot-password' '/reset-password'

#### Forgot Password Controller

#### Send Reset Password Email

#### Reset Password Controller

#### Hash Password Token
