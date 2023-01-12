const express = require('express')
const authController = require('./../controllers/authController')

const router = express.Router()

router.post('/sign-up', authController.signUp)
router.post('/verify-otp', authController.protectAuth, authController.OTPVerify)
router.post('/login', authController.login)
router.post('/check-login-on-start', authController.checkLoginOnStart)
router.post('/forgot-password', authController.forgotPassword)
router.post('/reset-password', authController.resetPassword)

module.exports = router