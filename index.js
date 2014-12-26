var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var crypto = require('crypto');
var async = require('async');

var TOKEN_LENGTH = 48;

var validity = 10 * 60 * 1000;

var token = Schema({
    created: {type: Date, default: Date.now},
    validity: {type: Number, default: validity},
    access: String,
    refresh: String,
    user: {type: Schema.Types.ObjectId, ref: 'User'},
    client: {type: Schema.Types.ObjectId, ref: 'Client'}
});

token.methods.valid = function () {
    return new Date().getTime() - this.created.getTime() < this.validity;
};

token.statics.search = function (value, cb) {
    this.findOne({
        value: value
    }).select('created validity').exec(function (err, token) {
        cb(err, (err || !token) ? false : token);
    });
};

token.pre('save', function (next) {
    var that = this;
    async.parallel([
            function (cb) {
                crypto.randomBytes(TOKEN_LENGTH, function (err, buf) {
                    if (err) {
                        cb(err);
                        return;
                    }
                    that.access = buf.toString('hex');
                    cb(null);
                });
            },
            function (cb) {
                crypto.randomBytes(TOKEN_LENGTH, function (err, buf) {
                    if (err) {
                        cb(err);
                        return;
                    }
                    that.refresh = buf.toString('hex');
                    cb(null);
                });
            }
        ],
        function (err, results) {
            next(err);
        });
});

token.virtual('id').get(function () {
    return this._id;
});

/*token.set('toJSON', {
 getters: true,
 virtuals: false,
 transform: function (doc, ret, options) {
 delete ret.hash;
 delete ret.salt;
 }
 });*/

/*token.virtual('password').set(function (password) {
 this.hash = '######';
 this.salt = '******';
 });*/
/*
 user.statics.find = function (options, callback) {
 if (options.email) {
 this.findOne({
 email: email
 }, callback);
 return;
 }
 callback(null);
 };*/

module.exports = mongoose.model('Token', token);