const sendErrorDev = (err, res) => {
  return res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  })
}

const sendErrorProduction = (err, res) => {
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    })
  }

  console.error('ERROR 💥', err)
  return res.status(500).json({
    status: 'error',
    message: 'Something went very wrong!',
  })
}

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500
  err.status = err.status || 'error'

  if (process.env.NODE_ENV === 'development') {
    return sendErrorDev(err, res)
  } else {
    return sendErrorProduction(err, res)
  }
}
