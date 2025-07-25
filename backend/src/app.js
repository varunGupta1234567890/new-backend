import express from "express"
import cors from "cors" //cross origin resource sharing browser security ke liye ye ek middleware hai
import cookieParser from "cookie-parser"//client server ke beech cookies handle karne ke liye

const app = express()
//isme express app ko setup karo
// const cors = require("cors");
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true // cookies ko allow kro
}))
//pehle models bnao phir usse controllers bnao fir unhe route kro or export kro fir routes ko app.js me import kro or use declare kro
app.use(express.json({limit: "16kb"}))//jab json se data aaye express ko btane ke liye
app.use(express.urlencoded({extended: true, limit: "16kb"}))//jab url se data aaye
app.use(express.static("public"))//public assets ke liye eg images , favicon
app.use(cookieParser())//server se user ki cookies access karne ke liye 

//routes import
import userRouter from './routes/user.routes.js'
import healthcheckRouter from "./routes/healthcheck.routes.js"
import tweetRouter from "./routes/tweet.routes.js"
import subscriptionRouter from "./routes/subscription.routes.js"
import videoRouter from "./routes/video.routes.js"
import commentRouter from "./routes/comment.routes.js"
import likeRouter from "./routes/like.routes.js"
import playlistRouter from "./routes/playlist.routes.js"
import dashboardRouter from "./routes/dashboard.routes.js"

//routes declaration
app.use("/api/v1/healthcheck", healthcheckRouter)
app.use("/api/v1/users", userRouter)
app.use("/api/v1/tweets", tweetRouter)
app.use("/api/v1/subscriptions", subscriptionRouter)
app.use("/api/v1/videos", videoRouter)
app.use("/api/v1/comments", commentRouter)
app.use("/api/v1/likes", likeRouter)
app.use("/api/v1/playlist", playlistRouter)
app.use("/api/v1/dashboard", dashboardRouter)





//http://localhost:8000/api/v1/users/register
export default app
//CORS KE OPTIONS H
//multer user se file lega or cloudnary upload karega