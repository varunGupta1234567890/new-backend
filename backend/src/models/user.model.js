import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true, 
            index: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true, 
        },
        fullName: {
            type: String,
            required: true,
            trim: true, 
            index: true
        },
        avatar: {
            type: String // cloudinary url 
           
        },
        coverImage: {
            type: String, // cloudinary url
        },
        watchHistory: [  //dependent on videos so contain multiple values so a array
            {
                type: Schema.Types.ObjectId,
                ref: "Video"
            }
        ],
        otp: {
        type: String
         },
        otpExpiry: {
         type: Date
        },
        otpEnabled: {
  type: Boolean,
  default: false
},


        password: {
            type: String,
            required: [true, 'Password is required'] //if want to give custom mssg use array
        },
        refreshToken: {
            type: String
        }

    },
    {
        timestamps: true //isse created at or updated at milte h
    }
)
//jab hum save pe click kare to password save ho jaye 
userSchema.pre("save", async function (next) {  // in fxn se pehle kya karwana h ye middleware h
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10)//use to save password everytime 10 rounds
    next()
})

userSchema.methods.isPasswordCorrect = async function(password){ //use to match psswords
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema)