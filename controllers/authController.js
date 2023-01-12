const jwt = require('jsonwebtoken')
const { User } = require('../models/userModel')
const CustomError = require('../utils/CustomError')

exports.signUp = async (req, res, next) => {
    try {
        const newUser = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: req.body.password
        })

        const token =  jwt.sign({ id : newUser._id}, process.env.JWT_SECRET)

        res.status(200).json({
            status: 'success',
            message: 'Your account has been created successfully.',
            token: token,
        })
    } catch (err) {
        return next(err)
    }
}

exports.protectAuth = async (req, res, next) => {
    try {
        let decoded
        let token

        if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
            token = await req.headers.authorization.split(' ')[1]
        }
        if(token === undefined){
            return next(new CustomError('You are not logged in.', 401))
        }
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET)
        } catch (err) {
            return next(err)
        }

        const freshUser = await User.findOne({id: decoded._id})
        if(!freshUser) return next(new CustomError('User has been deleted.', 401))

        req.user = freshUser
        next()
    } catch (err) {
        return next(err)
    }
}

exports.OTPVerify = async (req, res, next) => {
    try {
        const OTP = req.body.OTP
        const authToken = await req.headers.authorization.split(' ')[1]

        const decoded = jwt.verify(authToken, process.env.JWT_SECRET)

        const user = await User.findOne({_id: decoded.id})
        req.user = user

        if(!OTP){
            return next(new CustomError('Please enter the OTP.', 401))
        }
        const isOTPValid = await req.user.verifyOTP(OTP, req.user.OTP)

        if(isOTPValid) {
            await req.user.update({accountStatus: 'active'})
            await req.user.update({OTP : undefined})
            res.status(200).json({
                status: 'success',
                message: 'Your account has been activated.'
            })
        } else {
            res.status(401).json({
                status: 'fail',
                message: 'Invalid OTP'
            })
        }
        
    } catch (err) {
        return next(err)
    }
}

exports.login = async (req, res, next) => {
    // In ES6 if variable name == property name then we can just write {variable}
    const { email, password } = req.body

    // 1. Check if email and password exists
    if(!email || !password) {
        return next(new CustomError('Please provide a valid email and password.'), 400)
    }
    let user

    try {
        user = await User.findOne({ email }).select('+password')
        
        if(!user || !await user.checkPassword(password)) {
            return next(new CustomError('Entered email or password is incorrect.', 401))
        }
    } catch (err) {
        console.log(err)
    }

    const token = jwt.sign({ id : user._id}, process.env.JWT_SECRET)

    res.status(200).json({
        status:'success',
        token: token,
        message: 'You have successfully signed in.',
        account: user
    })
}


exports.checkLoginOnStart = async (req, res, next) => {
    let token
    let decoded

    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer ')){
        token = req.headers.authorization.split(' ')[1]
    }

    if(token === undefined){
        return next(new CustomError('You are not logged in.', 401))
    }

    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET)
    } catch (err) {
        return next(err)
    }    

    const freshUser = await User.findOne({id : decoded._id})
    if(!freshUser) return next(new CustomError('User has been deleted.', 401))

    res.status(200).json({
        status: 'success',
        message: 'User is logged in.'
    })
}


exports.forgotPassword = async (req, res, next) => {
    try {
        const { email } = req.body

        if(!email) {
            return next(new CustomError('Email not specified.', 401))
        }

        const user = await User.findOne({ email })

        if(!user){
            return next(new CustomError('No user found with given email.', 404))
        }

        try{
            await user.createPasswordResetOTP()
            user.save({validateBeforeSave : false})

            req.email = user.email

            res.status(200).json({
                status: 'success',
                message: 'An OTP has been created and sent to your email address.'
            })

        } catch(err){
            return next(err)
        }   

    } catch (err) {
        return next(err)
    }
}


exports.resetPassword = async (req, res, next) => {
    try {
        const OTP = req.body.OTP
        const newPassword = req.body.newPassword
        if(!OTP){
            return next(new CustomError('OTP not found.', 404))
        }

        const user = await User.findOne({ OTP })

        if(!user){
            return next(new CustomError('Entered OTP is not valid.', 400))
        }

        try {
            user.password = newPassword

            await user.save().then(async () => {
                await user.resetOTP()
                user.save({ validateBeforeSave: true })
            })

            res.status(200).json({
                status: 'success',
                message: 'Your password has been updated.'
            })

        } catch (err) {
            return next(err)
        }
        
    } catch (err) {
        return next(err)
    }
}