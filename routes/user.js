const router = require("express").Router();
const authController = require("../controllers/authController");
const userController = require("../controllers/userController");

router.patch("/update-me", authController.protect, userController.updateMe);
router.get("/get_users", authController.protect, userController.getUsers);
router.get("/get-requests", authController.protect, userController.getRequests);
router.get("/get-friends", authController.protect, userController.getFriends);

module.exports = router;
