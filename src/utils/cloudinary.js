//file already server pe upload ho chuki h it gives u local file path server se file loge or use cloudinary pe daloge uske baad file ko unlink kro
import dotenv from "dotenv";
dotenv.config({
    path:'./.env'});
import {v2 as cloudinary} from "cloudinary"
import fs from "fs"


//file system

cloudinary.config({ 
cloud_name:process.env.CLOUDINARY_CLOUD_NAME, 
api_key:process.env.CLOUDINARY_API_KEY, 
api_secret:process.env.CLOUDINARY_API_SECRET 
});

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null
        //upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        // file has been uploaded successfull
        //console.log("file is uploaded on cloudinary ", response.url);
        console.log("APIKEY",process.env.CLOUDINARY_API_KEY)
        fs.unlinkSync(localFilePath)
        return response;

    } catch (error) {
        console.log("cloudinary upload error",error)
        fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the upload operation got failed
        return null;
    }
}



export {uploadOnCloudinary}