const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const validator = require('validator')

const userSchema = new mongoose.Schema({
  role: {
    type: String,
    default: 'user',
    enum: ['user', 'admin'],
  },
  firstName: {
    type: String,
    required: [true, 'Please provide your full name.'],
  },
  lastName: {
    type: String,
    required: [true, 'Please provide your full name.'],
  },
  email: {
    type: String,
    required: [true, 'Please provide your email.'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email.'],
  },
  password: {
    type: String,
    minlength: 7,
    required: [true, 'Please provide your password.'],
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password.'],
    validate: {
      // This function only runs on CREATE and SAVE
      validator: function (el) {
        return el === this.password
      },
      message: 'Passwords do not match.',
    },
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
})

const capitalize = (string) => {
  return string.replace(string[0], string[0].toUpperCase())
}

userSchema.pre('save', function (next) {
  this.firstName = capitalize(this.firstName)
  this.lastName = capitalize(this.lastName)
  next()
})

userSchema.pre('findByIdAndUpdate', { document: true, query: false }, function (next) {
  if (!this.isModified('firstName')) return next()
  if (!this.isModified('lastName')) return next()

  this.firstName = capitalize(this.firstName)
  this.lastName = capitalize(this.lastName)
  next()
})

userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next()

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12)

  // Delete passwordConfirm field
  this.passwordConfirm = undefined
  next()
})

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword)
}

const User = mongoose.model('User', userSchema)

module.exports = User
