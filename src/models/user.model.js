import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

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
            lowecase: true,
            trim: true, 
        },
        fullName: {
            type: String,
            required: true,
            trim: true, 
            index: true
        },
        avatar: {
            type: String, // cloudinary url 
            required: true,
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

userSchema.pre("save", async function (next) {  // in fxn se pehle kya karwana h ye middleware h
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10)//use to save password everytime
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