const jwt = require('jsonwebtoken')
const { promisify } = require('util')

const catchAsync = require('../utils/catchAsync')
const AppError = require('../utils/appError')
const User = require('../models/userModel')

const createToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION,
  })
}

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  })

  const token = createToken(newUser.id)

  return res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser,
    },
  })
})

exports.login = catchAsync(async (req, res, next) => {
  if (!req.body.email || !req.body.password) {
    return next(new AppError('Invalid data submitted.', 400))
  }

  const user = await User.findOne({ email: req.body.email }).select('+password')
  if (!user || !(await user.correctPassword(req.body.password, user.password))) {
    return next(new AppError('Invalid email or password.', 401))
  }

  const token = createToken(user.id)
  user.password = undefined
  user.__v = undefined

  return res.status(200).json({
    status: 'success',
    token,
    data: {
      user,
    },
  })
})

exports.protect = catchAsync(async (req, res, next) => {
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer')) {
    return next(new AppError('You are not authorized to perform this action.', 401))
  }

  const token = req.headers.authorization.split(' ')[1]

  const decodedToken = await promisify(jwt.verify)(token, process.env.JWT_SECRET)
  const currentUser = await User.findById(decodedToken.id)

  if (!currentUser) {
    return next(new AppError('This user no longer exists.', 404))
  }

  req.user = currentUser
  next()
})

exports.restrictToAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return next(new AppError('This action can be performed by admin only.', 403))
  }

  next()
}
