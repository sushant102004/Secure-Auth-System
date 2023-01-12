const express = require('express')
const mongoose = require('mongoose')
const dotenv = require('dotenv')
const CustomError = require('./utils/CustomError')
const errorController = require('./controllers/errorController')
const userRouter = require('./routes/userRoutes')


dotenv.config()

const app = express()
app.use(express.json())

mongoose.set('strictQuery', false)

mongoose.connect(process.env.MONGODB_URI, () => {
    console.log('Connected to MongoDB')

    app.listen(process.env.PORT, () => {
        console.log('Listening on port: ' + process.env.PORT)
    })
})

app.use('/api/v1/users', userRouter)

app.get('*', (req, res, next) => {
    next(new CustomError(`The route ${req.originalUrl} is not defined.`, 400))
})

app.use(errorController)