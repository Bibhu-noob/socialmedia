const User = require("../models/User");
const jwt = require("jsonwebtoken");

exports.isAuthenticated = async (req, res, next) => {
  try {
    const { token } = req.cookies;

    if (!token) {
      return res.status(401).json({
        message: "Please login first",
      });
    }

    const decoded = await jwt.verify(token, process.env.JWT_SECRET);
    //jwt k method hai verify decoded mei ek object hga jiski koi id hogi
    //isse humko user ka id mil jayega

    req.user = await User.findById(decoded._id);
    //isse humko user mil jayega ,req.user mei sara data save hojayega

    next();
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};
