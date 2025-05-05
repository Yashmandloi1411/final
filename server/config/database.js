const mongoose = require("mongoose")
require("dotenv").config()

exports.connect = () => {
  mongoose
    .connect(process.env.DATABASE_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      console.log("DB connection is Done")
    })
    .catch((err) => {
      console.log("Error in DB connection:", err)
      process.exit(1)
    })
}

// const mongoose = require("mongoose")

// // dotenv
// require("dotenv").config()
// // connect to db
// exports.connect = mongoose
//   .connect(process.env.DATABASE_URL, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   })
//   .then(() => {
//     console.log("DB connection is Done")
//   })
//   .catch((err) => {
//     console.log("Error in DB connection:", err)
//     process.exit(1)
//   })

// const mongoose = require("mongoose")
// require("dotenv").config()

// const { MONGODB_URL } = process.env

// exports.connect = () => {
//   mongoose
//     .connect(MONGODB_URL, {
//       useNewUrlparser: true,
//       useUnifiedTopology: true,
//     })
//     .then(console.log(`DB Connection Success`))
//     .catch((err) => {
//       console.log(`DB Connection Failed`)
//       console.log(err)
//       process.exit(1)
//     })
// }
