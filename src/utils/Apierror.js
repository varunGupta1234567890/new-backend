class ApiError extends Error {
    constructor(    //initial state set karne ke liye constructor(initial){jo set karna h}
        statusCode,
        message= "Something went wrong",
        errors = [],
        stack = "" //stacktrace jo batata hai error kaha se aaya
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
            Error.captureStackTrace(this, this.constructor)//ye node.js ka method h jo error obj ke liye stack trace manually set karta h
        }

    }//jo fxn baar baar use honge use util me dalo
}

export {ApiError}




// import React, { Component } from 'react'

// export default class Apierror extends Component {
//   render() {
//     return (
//       <div>
        
//       </div>
//     )   rcc
//   }
// }
