const router = require("express").Router();
const authController = require("../controllers/authController");

router.post("/login", authController.login);
router.post("/register", authController.register);

router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);

router.post("/send-otp", authController.sendOtp);
router.post("/verify-otp", authController.verifyOtp);

module.exports = router;
