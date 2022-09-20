require('dotenv').config()
require('express-async-error')
const express = require('express')
const app = express()
const path = require('path')
const cors = require('cors')
const corsOptions = require('./config/corsOptions')
const cookieParser = require('cookie-parser')
const connectDB = require('./config/dbConn')
const mongoose = require('mongoose')
const PORT = process.env.PORT || 3000

const { logger, logEvents } = require('./middleware/logger')
const errorHandler = require('./middleware/errorHandler')

connectDB()

app.use(cors(corsOptions))
app.use(express.urlencoded({ extended: false }))
app.use(logger)
app.use(express.json())
app.use(cookieParser())

app.use('/', require('./routes/rootRoute'))
app.use('/users', require('./routes/userRoute'))
app.use('/auth', require('./routes/authRoute'))
app.use('/notes', require('./routes/noteRoutes'))
app.get('/healthz', (req, res) => {
  res.status(200).send('ok')
})

app.all('*', (req, res) => {
  res.status(404);
  if (req.accepts('html')) {
    res.sendFile(path.join(__dirname, 'views', '404.html'));
  } else if (req.accepts('json')) {
    res.json({ "error": "404 Not Found" });
  } else {
    res.type('txt').send("404 Not Found");
  }
})

app.use(errorHandler)


mongoose.connection.once('open', () => {
  console.log('Connected to MongoDB')
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
})

mongoose.connection.on('error', err => {
  console.log(err)
  logEvents(`${err.no}: ${err.code}\t${err.syscall}\t${err.hostname}`, 'mongoErrLog.log')
})