//require('dotenv').config({path:'./env'})
import dotenv from "dotenv"
dotenv.config({
    path:'./.env'
})
// import connectdb from "./db/index.js"
// import app from './app.js';

import connectdb from "./db/index.js"
import app from './app.js';


//db wale index me connectdb function bnaya h or use main index me call kiya h
connectdb()
.then(() => {
    app.listen(process.env.PORT || 8000, () => {
        console.log(` Server is running at port : ${process.env.PORT}`);
    })
})
.catch((err) => {
    console.log("MONGO db connection failed !!!",err);
})







// import express from "express"
// const app = express()



// ( async () => {
//     try {
//        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
//        app.on("error", (error) =>{
//         console.log("err:",error)
//         throw error
//        })
//        app.listen(process.env.PORT, () => {
//         console.log(`App is listening on "http://localhost:${process.env.PORT}"`)
//        })
//     } catch (error) {
//         console.error("error:",error)
//         throw err
//     }
// })()