import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";
import bcrypt from 'bcryptjs';
import { sendOtp } from "../utils/sendOtp.js";


const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
    //refreshtoken ko db me save kraya   access token already db me save hota h
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}


    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary,check avatar is uploaded or not
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return response otherwise return error


const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, username, password } = req.body;

  // 1. Check empty fields
  if ([fullName, email, username, password].some((field) => field?.trim() === "")) {
    throw new ApiError(400, "All fields are required");
  }
   // Email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ApiError(400, "Please enter a valid email address");
  }

  // 2. Password Strength Warning
  if (password.length < 6 || !/[A-Z]/.test(password) || !/\d/.test(password)) {
    throw new ApiError(
      400,
      "Password should be at least 6 characters, include one uppercase letter and one number"
    );
  }

  // 3. Check existing user
  const existedUser = await User.findOne({
    $or: [{ username }, { email }]
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // 4. Hash password
//   const hashedPassword = await bcrypt.hash(password, 10);

  // 5. Create user
  const user = await User.create({
    fullName,
    email,
    password,
    // password,
    username: username.toLowerCase()
  });

  // 6. Confirm creation
  const createdUser = await User.findById(user._id).select("-password -refreshToken");

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // 7. Send response
  return res.status(201).json(
    new ApiResponse(201, createdUser, "User registered successfully")
  );
});



   
   

      
// <-------------------------------------------- login------------------------------------------------->
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie
const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if (!username && !email) {
    throw new ApiError(400, "Email or username are required");
  }

  if (!email || !password) {
    throw new ApiError(400, "Email and password are required");
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ApiError(400, "Please enter a valid email address");
  }

  const user = await User.findOne({ $or: [{ username }, { email }] });
  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid credentials");
  }

  // ✅ Force OTP for every user
  const otp = Math.floor(100000 + Math.random() * 900000);
  user.otp = otp;
  user.otpExpiry = Date.now() + 5 * 60 * 1000;
  await user.save({ validateBeforeSave: false });

  await sendOtp(user.email, otp);

  const tempToken = jwt.sign(
    { userId: user._id, email: user.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "5m" }
  );

  return res.status(200).json({
    success: true,
    otpRequired: true,
    accessToken: tempToken,
    message: "OTP sent to your email",
  });
});

// if (user.otpEnabled) {
//   // ✅ Step 1: Generate OTP
//   const generatedOtp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
//   user.otp = generatedOtp;
//   user.otpExpiry = Date.now() + 5 * 60 * 1000; // 5 minutes expiry

//   // ✅ Step 2: Save OTP in DB
//   await user.save({ validateBeforeSave: false });

//   // ✅ Step 3: Send OTP to user email
//   await sendOtp(user.email, generatedOtp);

  // ✅ OTP logic for every user (force OTP)
 

//   // ✅ Normal login if OTP not enabled
//   const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id);

//   const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

//   const options = {
//     httpOnly: true,
//     secure: true,
//   };

//   return res
//     .status(200)
//     .cookie("accessToken", accessToken, options)
//     .cookie("refreshToken", refreshToken, options)
//     .json(
//       new ApiResponse(
//         200,
//         {
//           success: true,
//           user: loggedInUser,
//           accessToken,
//           refreshToken,
//         },
//         "User logged in successfully"
//       )
//     );
// };



 const verifyOtp = asyncHandler (async(req, res) => {
  try {
    const { otp } = req.body;

    // Step 1: Extract temp token from headers
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new ApiError(401, "Missing or invalid token");
    }

    const token = authHeader.split(" ")[1];

    // Step 2: Verify temp token
    let payload;
    try {
      payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (err) {
      throw new ApiError(401, "Token expired or invalid");
    }

    // Step 3: Find user
    const user = await User.findById(payload.userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    // Step 4: Check OTP match
    if (user.otp !== otp) {
      throw new ApiError(400, "Invalid OTP");
    }

    // Step 5: Check if OTP expired
    if (user.otpExpiry < Date.now()) {
      throw new ApiError(400, "OTP has expired");
    }

    // Step 6: Clear OTP fields
    user.otp = null;
    user.otpExpiry = null;
    await user.save({ validateBeforeSave: false });

    // Step 7: Issue access & refresh token
    const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id);
    const safeUser = await User.findById(user._id).select("-password -refreshToken");

    // Step 8: Send response
    return res
      .status(200)
      .cookie("accessToken", accessToken, { httpOnly: true })
      .cookie("refreshToken", refreshToken, { httpOnly: true })
      .json(
        new ApiResponse(
          200,
          {
            success: true,
            user: safeUser,
            accessToken,
            refreshToken,
          },
          "OTP verified successfully"
        )
      );

  } catch (err) {
    console.error("OTP Verify Error:", err.message);
    return res.status(err.statusCode || 500).json({
      success: false,
      message: err.message || "OTP verification failed",
    });
  }
}
 )








const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,//user find kro
        {
            $unset: { //update
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }
 //auth middleware user ko logout karane ke liye banaya h
    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
// server se refresh token access lo(via cookies or body) or apne refresh Token se match kro or access token ko regenerate kro
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }
  //ab token verify kro or user find kro
    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
            
        }
    //ab new tokens generate kro pehle cookies me bhejna h
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200, 
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})


const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldpassword, newpassword } = req.body;

  //  1. Check if new password is strong enough
  if (
    newpassword.length < 6 ||
    !/[A-Z]/.test(newpassword) ||
    !/\d/.test(newpassword)
  ) {
    throw new ApiError(
      400,
      "Password should be at least 6 characters long, contain one uppercase letter and one number"
    );
  }

  //  2. Find user from token
  const user = await User.findById(req.user?._id);
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  //  3. Verify old password
  const isPasswordCorrect = await user.isPasswordCorrect(oldpassword);
  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid old password");
  }

//   //  4. Hash new password
//   const hashedPassword = await bcrypt.hash(newpassword, 10);
//   user.password = hashedPassword;
user.password=newpassword;
  //  5. Save user
  await user.save();

  //  6. Respond
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

// ---------------------------------------------------------------------

// const bcrypt = require('bcryptjs'); iski jagh import use kro
const forgotPassword = asyncHandler(async (req, res) => {
  const { email, newpassword } = req.body;

  //  Input validation
  if (!email || !newpassword) {
    throw new ApiError(400, "Email and new password are required");
  }

  // Email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ApiError(400, "Please enter a valid email address");
  }
  //  Password strength check
  if (
    newpassword.length < 6 ||
    !/[A-Z]/.test(newpassword) ||
    !/\d/.test(newpassword)
  ) {
    throw new ApiError(
      400,
      "Password must be at least 6 characters, include an uppercase letter and a number"
    );
  }

  //  Check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "User not found with this email");
  }

  //  Hash and save new password
//   const hashedPassword = await bcrypt.hash(newpassword, 10);
//   user.password = hashedPassword;
user.password=newpassword;
  await user.save();

  // Final response
  return res.status(200).json({
    success: true,
    message: "Password changed successfully",
  });
});



const getCurrentUser = asyncHandler(async(req, res) => {
    return res
    .status(200)
    .json(new ApiResponse(
        200,
        req.user,  //data
        "User fetched successfully"
    ))
})

const updateAccountDetails = asyncHandler(async(req, res) => {
    const {fullName, email,otpEnabled} = req.body//jo-jo hum update karana chahte hai

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }
// Email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new ApiError(400, "Please enter a valid email address");
  }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email: email,//dono tarah se de sakte h,
                otpEnabled:otpEnabled
            }
        },
        {new: true} //3rd field after update
        
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
});

const updateUserAvatar = asyncHandler(async(req, res) => {
    //file change jarne se pehle user se uska path lo
    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    //TODO: delete old image - assignment

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")
        
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar image updated successfully")
    )
})

const updateUserCoverImage = asyncHandler(async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover image file is missing")
    }

    //TODO: delete old image - assignment


    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw new ApiError(400, "Error while uploading on avatar")
        
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover image updated successfully")
    )
})


const getUserChannelProfile = asyncHandler(async(req, res) => {
    const {username} = req.params //hame uske url se chahiye

    if (!username?.trim()) {
        throw new ApiError(400, "username is missing")
    }

    const channel = await User.aggregate([  //aggregate pipeline or isse array aate h
        {
            $match: {
                username: username?.toLowerCase()//isme user ko match kiya h
            }
        },
        {
            $lookup: {        //subscribers find karne ke liye
                from: "subscriptions",  //ye models hai to isme lower case ho jayega or ending with s hoga
                localField: "_id",
                foreignField: "channel", //channel select karne se subs milenge
                as: "subscribers" //kuch name dena h
            }
        },
        {
            $lookup: { //subscribed (kisko subs kar rakha h) nikalne ke liye
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {  //ab dono uper ki fields ko original user field me add karna h
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {//subscribe button ke liye
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: { //kis-kis ko cover page pe dikhana h
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1

            }
        }
    ])

    if (!channel?.length) {
        throw new ApiError(404, "channel does not exists")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200, channel[0], "User channel fetched successfully")
    )
})

const getWatchHistory = asyncHandler(async(req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {  //videos lene ke liye
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [ //sub pipeline
                    {
                        $lookup: {  //users se lookup karna h uski saari details aayengi isse
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {//ye sara hamara owner field me jayega
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"//array me se first value nikalni h field me se bcoz lookup array deta h
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "Watch history fetched successfully"
        )
    )
})


export {
    registerUser,
    loginUser,
    logoutUser,
    forgotPassword,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory,
    verifyOtp
}
