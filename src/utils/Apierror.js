class ApiError extends Error {
    constructor(    //initial state set karne ke liye
        statusCode,
        message= "Something went wrong",
        errors = [],
        stack = ""
    ){
        //ye work set karna h //constructor class based component hota h isliye this. use kiya h
        super(message)//saare overwrite karne h
        this.statusCode = statusCode
        this.data = null
        this.message = message
        this.success = false;
        this.errors = errors

        if (stack) {
            this.stack = stack
        } else{
            Error.captureStackTrace(this, this.constructor)
        }

    }
}

export {ApiError}