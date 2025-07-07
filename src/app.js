import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

app.use(express.json({limit: "16kb"}))//jab json se data aaye express ko btane ke liye
app.use(express.urlencoded({extended: true, limit: "16kb"}))//jab url se data aaye
app.use(express.static("public"))//public assets ke liye eg images , favicon
app.use(cookieParser())//server se user ki cookies access karne ke liye 

export {app}
//CORS KE OPTIONS H