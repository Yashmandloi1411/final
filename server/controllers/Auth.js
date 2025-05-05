const bcrypt = require("bcrypt")
const User = require("../models/User")
const OTP = require("../models/OTP")
const jwt = require("jsonwebtoken")
const otpGenerator = require("otp-generator")
const mailSender = require("../utils/mailSender")
const { passwordUpdated } = require("../mail/templates/passwordUpdate")
const Profile = require("../models/Profile")
require("dotenv").config()

// Signup Controller for Registering USers

exports.signup = async (req, res) => {
  try {
    // Destructure fields from the request body
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body
    // Check if All Details are there or not
    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !confirmPassword ||
      !otp
    ) {
      return res.status(403).send({
        success: false,
        message: "All Fields are required",
      })
    }
    // Check if password and confirm password match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message:
          "Password and Confirm Password do not match. Please try again.",
      })
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists. Please sign in to continue.",
      })
    }

    // Find the most recent OTP for the email
    const response = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1)
    console.log(response)
    if (response.length === 0) {
      // OTP not found for the email
      return res.status(400).json({
        success: false,
        message: "The OTP is not valid",
      })
    } else if (otp !== response[0].otp) {
      // Invalid OTP
      return res.status(400).json({
        success: false,
        message: "The OTP is not valid",
      })
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Create the user
    let approved = ""
    approved === "Instructor" ? (approved = false) : (approved = true)

    // Create the Additional Profile For User
    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null,
    })
    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber,
      password: hashedPassword,
      accountType: accountType,
      approved: approved,
      additionalDetails: profileDetails._id,
      image: "",
    })

    return res.status(200).json({
      success: true,
      user,
      message: "User registered successfully",
    })
  } catch (error) {
    console.error(error)
    return res.status(500).json({
      success: false,
      message: "User cannot be registered. Please try again.",
    })
  }
}

// Login controller for authenticating users
exports.login = async (req, res) => {
  try {
    // Get email and password from request body
    const { email, password } = req.body

    console.log("Login attempt with:", email, password)

    // Check if email or password is missing
    if (!email || !password) {
      // Return 400 Bad Request status code with error message
      return res.status(400).json({
        success: false,
        message: `Please Fill up All the Required Fields`,
      })
    }

    // Find user with provided email
    const user = await User.findOne({ email }).populate("additionalDetails")

    // If user not found with provided email
    if (!user) {
      console.log("User not found for email:", email)
      // Return 401 Unauthorized status code with error message
      return res.status(401).json({
        success: false,
        message: `User is not Registered with Us Please SignUp to Continue`,
      })
    }

    console.log("User found. Comparing passwords...")
    console.log("Entered Password:", password)
    console.log("Hashed Password from DB:", user.password)

    // Generate JWT token and Compare Password
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign(
        { email: user.email, id: user._id, role: user.role },
        process.env.JWT_SECRET,
        {
          expiresIn: "24h",
        }
      )

      // Save token to user document in database
      user.token = token
      user.password = undefined
      // Set cookie for token and return success response
      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      }
      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: `User Login Success`,
      })
    } else {
      console.log("Password is incorrect for email:", email)
      return res.status(401).json({
        success: false,
        message: `Password is incorrect`,
      })
    }
  } catch (error) {
    console.error("Login error:", error)
    // Return 500 Internal Server Error status code with error message
    return res.status(500).json({
      success: false,
      message: `Login Failure Please Try Again`,
    })
  }
}
// Send OTP For Email Verification
exports.sendotp = async (req, res) => {
  try {
    const { email } = req.body

    // Check if user is already present
    // Find user with provided email
    const checkUserPresent = await User.findOne({ email })
    // to be used in case of signup

    // If user found with provided email
    if (checkUserPresent) {
      // Return 401 Unauthorized status code with error message
      return res.status(401).json({
        success: false,
        message: `User is Already Registered`,
      })
    }

    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    })
    console.log("OTP generated:", otp)

    const result = await OTP.findOne({ otp: otp })
    console.log("Result is Generate OTP Func")
    console.log("OTP", otp)
    console.log("Result", result)
    while (result) {
      otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        specialChars: false,
        lowerCaseAlphabets: false,
      })

      result = await OTP.findOne({ otp: otp })
    }
    const otpPayload = { email, otp }
    const otpBody = await OTP.create(otpPayload)

    console.log("OTP Body", otpBody)

    res.status(200).json({
      success: true,
      message: `OTP Sent Successfully`,
      otp,
    })
  } catch (error) {
    console.log(error.message)
    return res.status(500).json({ success: false, error: error.message })
  }
}

// Controller for Changing Password
exports.changePassword = async (req, res) => {
  try {
    // Get user data from req.user
    const userDetails = await User.findById(req.user.id)

    // Get old password, new password, and confirm new password from req.body
    const { oldPassword, newPassword } = req.body

    // Validate old password
    const isPasswordMatch = await bcrypt.compare(
      oldPassword,
      userDetails.password
    )
    if (!isPasswordMatch) {
      // If old password does not match, return a 401 (Unauthorized) error
      return res
        .status(401)
        .json({ success: false, message: "The password is incorrect" })
    }

    // Update password
    const encryptedPassword = await bcrypt.hash(newPassword, 10)
    const updatedUserDetails = await User.findByIdAndUpdate(
      req.user.id,
      { password: encryptedPassword },
      { new: true }
    )

    // Send notification email
    try {
      const emailResponse = await mailSender(
        updatedUserDetails.email,
        "Password for your account has been updated",
        passwordUpdated(
          updatedUserDetails.email,
          `Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
        )
      )
      console.log("Email sent successfully:", emailResponse.response)
    } catch (error) {
      // If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
      console.error("Error occurred while sending email:", error)
      return res.status(500).json({
        success: false,
        message: "Error occurred while sending email",
        error: error.message,
      })
    }

    // Return success response
    return res
      .status(200)
      .json({ success: true, message: "Password updated successfully" })
  } catch (error) {
    // If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
    console.error("Error occurred while updating password:", error)
    return res.status(500).json({
      success: false,
      message: "Error occurred while updating password",
      error: error.message,
    })
  }
}

// send OTP
// exports.sendOTP = async (req, res) => {
//   try {
//     const { email } = req.body;
//     // check user alredy exist
//     const checkUserPresent = await User.findOne({ email });
//     if (checkUserPresent) {
//       return res.status(401).json({
//         success: false,
//         message: "User already register",
//       });
//     }

//     // otp generate

//     var otp = otpGenerator.generate(6, {
//       upperCaseAlphabets: false,
//       specialChars: false,
//       lowerCaseAlphabets: false,
//     });

//     console.log("OTP generated:", otp);

//     // otp unique hona chiya if otp exist ha to vapas bhaj dega

//     const result = await OTP.findOne({ otp: otp });
//     console.log("Result is Generate OTP Func");
//     console.log("OTP", otp);
//     console.log("Result", result);

//     while (result) {
//       otp = otpGenerator.generate(6, {
//         upperCaseAlphabets: false,
//         specialChars: false,
//         lowerCaseAlphabets: false,
//       });

//       result = await OTP.findOne({ otp: otp });
//     }

//     // apko otp ki entry db me kari ha

//     const otpPayload = { email, otp };

//     // const otpBody = await OTP.create({ otpPayload });

//     const otpBody = await OTP.create(otpPayload);

//     console.log("OTP Body", otpBody);

//     return res.status(200).json({
//       success: true,
//       message: "Otp send successfully",
//       otp,
//     });
//   } catch (err) {
//     console.log(err);
//     return res.status(400).json({
//       success: false,
//       message: " Failed to send Otp:",
//     });
//   }
// };

// signUp
// exports.signUp = async (req, res) => {
//   try {
//     // data fetch from req ki body
//     const {
//       firstName,
//       lastName,
//       email,
//       phone,
//       password,
//       confirmPassword,
//       otp,
//       accountType,
//     } = req.body;

//     console.log("all data signup:", req.body);
//     //user is exist or not

//     //validation karlo
//     if (
//       !firstName ||
//       !lastName ||
//       !email ||
//       !password ||
//       !confirmPassword ||
//       !otp
//     ) {
//       return res.status(403).json({
//         success: false,
//         message: "All field are required!",
//       });
//     }
//     //2 password match karlo
//     if (password !== confirmPassword) {
//       return res.status(400).json({
//         success: false,
//         message: "Password and Confirmed password value doesn't matched!",
//       });
//     }

//     //check user already exist or not
//     const existUser = await User.findOne({ email });
//     if (existUser) {
//       return res.status(400).json({
//         success: false,
//         message: "User is already registered",
//       });
//     }

//     // find most recent OTP stored for the user
//     const recentOtp = await OTP.find({ email })
//       .sort({ createdAt: -1 })
//       .limit(1);

//     console.log("recent otp:", recentOtp);

//     // validate otp
//     if (recentOtp.length === 0) {
//       // otp not found
//       return res.status(400).json({
//         success: false,
//         message: "OTP not found",
//       });
//     } else if (recentOtp[0].otp !== otp) {
//       // invalid otp

//       return res.status(400).json({
//         success: false,
//         message: "Invalid OTP",
//       });
//     }

//     // Hash password

//     let hashedpassword;
//     try {
//       hashedpassword = await bcrypt.hash(password, 10);
//     } catch (err) {
//       return res.status(400).json({
//         success: false,
//         message: "Error in hashing password !",
//       });
//     }

//     // creat a entry of user in DB

//     const profileDetails = await Profile.create({
//       // starting ma signup karte samay muja in details ki need nhi ha
//       // ham user sa nhi mangaga isliya null kardiya
//       dob: null,
//       gender: null,
//       about: null,
//       phone: null,
//     });

//     const user = await User.create({
//       email,
//       firstName,
//       lastName,
//       phone,
//       password: hashedpassword,
//       confirmPassword,
//       otp,
//       accountType,
//       additionalDetails: profileDetails._id,
//       image: `https://api.dicebear.com/9.x/initials/svg?seed=${firstName} ${lastName}`,
//     });

//     // return res
//     return res.status(200).json({
//       success: true,
//       message: "User is created successfully",
//     });
//   } catch (err) {
//     console.log(err);
//     return res.status(400).json({
//       success: false,
//       message: " Failed to SignUp:",
//     });
//   }
// };

// login

// exports.login = async (req, res) => {
//   try {
//     // get data from user body

//     const { email, password } = req.body
//     // validation data
//     if (!email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: "All field are required for Login, please try again ",
//       })
//     }
//     // user check exist or not
//     const userexist = await User.findOne({ email }).populate(
//       "additionalDetails"
//     )

//     if (!userexist) {
//       return res.status(401).json({
//         success: false,
//         message: "User is not register, plz try again",
//       })
//     }

//     // generate JWT, after password matching
//     // compare password

//     if (await bcrypt.compare(password, userexist.password)) {
//       const payload = {
//         email: userexist.email,
//         id: userexist._id,
//         accountType: userexist.accountType,
//       }
//       const token = jwt.sign(payload, process.env.JWT_SECRET, {
//         expiresIn: "2h",
//       })

//       ;(userexist.token = token), (userexist.password = undefined)

//       // create cookie and send response

//       const options = {
//         expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
//         httpOnly: true,
//       }

//       res.cookie("token", token, options).status(200).json({
//         success: true,
//         token,
//         userexist,
//         message: `user Login Success`,
//       })
//     } else {
//       return res.status(400).json({
//         success: false,
//         message: "Password are not matching",
//       })
//     }
//   } catch (err) {
//     console.error(err)
//     return res.status(500).json({
//       success: false,
//       message: "Failed to Login Enter correct Field:",
//     })
//   }
// }

// changed password
//HOME: TODO
// exports.changePassword = async (req, res) => {
//   try {
//     // get data from req body
//     const { email, oldpassword, newpassword, confirmpassword } = req.body;

//     if (!email || !oldpassword || !newpassword || !confirmpassword) {
//       return res.status(400).json({
//         success: false,
//         message:
//           "ALL fields email, oldpassword,newpassword, confirmpassword required!",
//       });
//     }

//     // check if user is exist

//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(400).json({
//         success: false,
//         message: "user is not exist",
//       });
//     }

//     const isMatch = await bcrypt.compare(newpassword, User.password);
//     if (!isMatch) {
//       return res.status(401).json({
//         success: false,
//         message: "Incorrect  old password",
//       });
//     }

//     if (newpassword !== confirmpassword) {
//       return res.staus(401).json({
//         success: false,
//         message: "New password and confirm password do not match!",
//       });
//     }

//     // Hash new password before saving
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(newPassword, salt);

//     // Update password in the database
//     user.password = hashedPassword;
//     await user.save();

//     // Send password update email (Assuming sendEmail function exists)
//     await sendEmail(
//       user.email,
//       "Password Updated",
//       "Your password has been successfully updated."
//     );

//     return res.status(200).json({
//       success: true,
//       message: "Password updated successfully!",
//     });

//     // get oldpassword, new password, confirmNewPassword
//     // validation

//     // update password  in DB

//     // send mail - password Update
//     // return response
//   } catch (err) {
//     return res.status(500).json({
//       success: false,
//       message: "Failed to update password!",
//     });
//   }
// };
