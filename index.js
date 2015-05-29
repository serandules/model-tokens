var mongoose = require('mongoose');

module.exports = mongoose.model('Token') || require('./model');