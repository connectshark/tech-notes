const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  line_id: {
    type: String,
    required: true
  },
  email: {
    type: String,
    lowercase: true
  },
  created_at: {
    type: Date,
    immutable: true,
    default: () => Date.now
  },
  update_at: {
    type: Date,
    default: () => Date.now
  },
  active: {
    type: Boolean,
    default: true
  }
})

userSchema.pre('save', function (next) {
  this.update_at = Date.now()
  next()
})

module.exports = mongoose.model('User', userSchema)