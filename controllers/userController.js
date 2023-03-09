const User = require("../models/user");

exports.updateMe = async (req, res, next) => {
  const { user } = req;

  const filterBody = filterObj(req.body, "firstName", "lastName", "email");

  const updated_user = await User.findByIdAndUpdate(user._id, filterBody, {
    new: true,
    validateModifiedOnly: true,
  });

  res.staus(200).json({
    status: "success",
    data: updated_user,
    message: "Profile Update successfully",
  });
};
