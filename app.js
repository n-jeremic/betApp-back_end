const express = require('express')
const path = require('path')
const cors = require('cors')

const userRouter = require('./routes/userRoutes')
const errorController = require('./controllers/errorController')
const AppError = require('./utils/appError')

const app = express()

// GLOBAL MIDDLEWARE STACK
app.use(cors())
app.options('*', cors())

app.use(express.json({ limit: '10kb' }))
app.use(express.static(path.join(__dirname, 'public')))

// ROUTES
app.use('/api/users', userRouter)

// ERROR HANDLING
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server`, 404))
})

app.use(errorController)

module.exports = app
