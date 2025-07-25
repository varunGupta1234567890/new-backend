import multer from "multer";

const storage = multer.diskStorage({   //use as middleware
    destination: function (req, file, cb) {
      cb(null, "./public/temp") //callback//client se aayi file ko public temp me store karta h
    },
    filename: function (req, file, cb) {
      
      cb(null, file.originalname)
    }
  })
  //middleware setup
export const upload = multer({ 
    storage, 
})