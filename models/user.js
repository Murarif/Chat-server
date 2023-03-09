const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  firsName: {
    type: String,
    required: [true, "First Name is required"],
  },
  lastName: {
    type: String,
    required: [true, "Last Name Name is required"],
  },
  avatar: {
    type: String,
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    validate: {
      validator: function (email) {
        return String(email)
          .toLowerCase()
          .match(
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
          );
      },
      message: (props) => `Email (${props.value}) is invalid!`,
    },
  },
  password: {
    type: String,
  },
  passwordConfirm: {
    type: String,
  },
  passwordChangeAt: {
    type: Date,
  },
  passwordResetToken: {
    type: String,
  },
  passwordResetExpires: {
    type: Date,
  },
  createdAt: {
    type: Date,
  },

  updateAt: {
    type: Date,
  },

  verified: {
    type: Boolean,
    default: false,
  },
  otp: {
    type: Number, // ssdfjdad991 erwqer81
  },
  otp_expiry_time: {
    type: Date,
  },
});

userSchema.pre("save", async function (next) {
  // Only run this fxn if OTP is actually modified

  if (!this.isModified("otp")) return next();

  // Hash the OTP wiht the cost of 12
  this.otp = await bcrypt.hash(this.otp, 12);

  next();
});

userSchema.pre("save", async function (next) {
  // Only run this fxn if OTP is actually modified

  if (!this.isModified("password")) return next();

  // Hash the OTP wiht the cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  next();
});

userSchema.method.correctPassword = async function (
  candidatePassword, // 123456
  userPassword // Arif19983434
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.method.correctOTP = async function (
  candidateOTP, // 123456
  userOTP // Arif19983434
) {
  return await bcrypt.compare(candidateOTP, userOTP);
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex ");

  this.passwordResetExpires = Date.now() + 10 * 6 * 100;

  return resetToken;
};

userSchema.methods.changedPasswordAfter = function (timestamp) {
  return timestamp < this.passwordChangeAt;
};

const User = new mongoose.model("User", userSchema);

module.exports = User;
