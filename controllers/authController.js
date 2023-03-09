const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const crypto = require("crypto");

const mailService = require("../services/mailer");
//

const User = require("../models/user");
const { promisify } = require("util");

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

// Signup => register - sendOTP  - verifyOTP

// https://api.tawk.com/auth/register

// Register New user
exports.register = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  const filteredBody = filterObj(
    req.body,
    "firtName",
    "LastName",
    "Password",
    "email"
  );

  // check if a verifed user with given email exists

  const existing_user = await User.findOne({ email: email });

  if (existing_user && existing_user.verified) {
    res.status(400).json({
      status: "error",
      message: "Email is already in use, Please login",
    });
  } else if (existing_user) {
    await User.findOneAndUpdate({ email: email }, { firstName }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });

    // generate OTP and send email to user
    req.userId = existing_user._id;
    next();
  } else {
    // if user record is not available id DB

    const new_user = await User.create(filteredBody);

    // generate OTP and send email to user

    req.userId = new_user._id;

    next();
  }
};

exports.sendOTP = async (req, res, next) => {
  const { userId } = req;
  const new_otp = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  const otp_expiry_time = Date.now() + 10 * 60 * 1000; // 10 mins after otp is send

  await User.findByIdAndUpdate(userId, {
    otp: new_otp,
    otp_expiry_time,
  });

  // TODO sen mail

  mailService
    .sendMail({
      from: "contact@murarif.in",
      to: "example@gmail.com",
      subject: "OTP for tawk",
      text: `Your OTP is ${new_otp} This is valid for 10 mins`,
    })
    .then(() => {})
    .catch((error) => {});

  res.status(200).json({
    status: "success",
    message: "OTP Sent Successfuly",
  });
};

exports.verifyOTP = async (req, res, next) => {
  // verify OTP and update user record accordingly

  const { email, otp } = req.body;

  const user = await User.findOne({
    email,
    otp_expiry_time: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Email is Invalid or OTP expired",
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "error",
      message: "OTP is incorrect",
    });
  }

  // OTP is correct

  user.verified = true;
  user.otp = undefined;

  await user.save({ new: true, validateModifiedOnly: true });

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "OTP verified successfully!",
    token,
  });
};

exports.login = async (req, res, next) => {
  //

  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });
  }

  const userDoc = await User.findOne({ email: email }).select("+password");

  if (!userDoc || (await userDoc.correctPassword(password, userDoc.password))) {
    res.status(400).json({
      status: "error",
      message: "Email or password is incorret",
    });
  }

  const token = signToken(userDoc._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully",
    token,
  });
};

exports.protect = async (req, res, next) => {
  //  1) Gettering token (JWT) and check if it's there

  let token;

  // "Bearer ksdfddf213232"

  if (
    req.header.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    req.status(400).json({
      status: "error",
      message: "You are not logged In! Please log in to get access",
    });
    return;
  }

  // 2) verification of token

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exist

  const this_user = await User.findById(decoded.userId);

  if (!this_user) {
    res.status(400).json({
      status: "error",
      message: "The user dosen't exist",
    });
  }

  // 4) check if user changed their password after token was issued

  if (this_user.changedPasswordAfter(decode.iat)) {
    res.status(400).json({
      status: "error",
      message: "User recently update Password! log in again",
    });
  }

  //
  req.user = this_user;
  next();
};

// Types of routes -> Proctected (Only logged in users can access these) &

exports.forgotPassword = async (req, res, next) => {
  // 1 ) Get users email
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "There is no user with given email address",
    });
    return;
  }

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetTokon();

  const resetURl = `https://tawk.com/auth/reset-password/?code${resetToken}`;

  try {
    // TODO => send Email
    res.status(200).json({
      status: "success",
      message: "Reset Password link sent to email.",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });
    res.status(500).json({
      status: "error",
      message: "There was an error sending the mail. Please try again leter",
    });
  }

  // https: // ?code
};

exports.resetPassword = async (req, res, next) => {
  // 1) Get user  based on token

  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");
  // console.log(hashedToken,"hashed -------------- token")
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // console.log(user, "userrrrrrrrrrrrrrr")

  // 2) if token has expired or submission is out of window
  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Token is invalid or Expired",
    });
    return;
  }

  // 3) update user password and set resetToken & expiry to unefined

  user.password = req.body.password; // 21324342eewr
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();

  // 4) login user and send  new JWT

  // TODO => send an email to user informing abaout password reset

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "Password Reseted Succesfully",
    token,
  });
};
