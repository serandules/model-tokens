var log = require('logger')('token');
var mongoose = require('mongoose');
var autopopulate = require('mongoose-autopopulate');
var Schema = mongoose.Schema;
var crypto = require('crypto');
var async = require('async');
var Lock = require('lock');

var permission = require('permission');

var TOKEN_LENGTH = 48;

var accessibility = 60 * 1000;
var refreshability = 10 * accessibility;

var token = Schema({
    created: {type: Date, default: Date.now},
    access: String,
    accessible: {type: Number, default: accessibility},
    refresh: String,
    refreshable: {type: Number, default: refreshability},
    user: {type: Schema.Types.ObjectId, ref: 'User', autopopulate: true},
    client: {type: Schema.Types.ObjectId, ref: 'Client', autopopulate: true},
    has: {
        type: Object, default: {
            '*': {
                '': ['*']
            }
        }
    },
    allowed: {type: Object, default: {}}
});

token.plugin(autopopulate);

token.set('toJSON', {
    getters: true,
    //virtuals: false,
    transform: function (doc, ret, options) {
        delete ret._id;
    }
});

token.methods.accessibility = function () {
    var exin = this.created.getTime() + this.accessible - new Date().getTime();
    return exin > 0 ? exin : 0;
};

token.methods.refreshability = function () {
    var exin = this.created.getTime() + this.refreshable - new Date().getTime();
    return exin > 0 ? exin : 0;
};

token.methods.can = function (perm, action, o) {
    var trees = [this.has, this.client.has];
    return permission.every(trees, perm, action) &&
        permission.least(o.allowed, 'users:' + this.user.id, action);
};

token.statics.search = function (value, cb) {
    this.findOne({
        value: value
    }).select('created accessible').exec(function (err, token) {
        cb(err, (err || !token) ? false : token);
    });
};

token.pre('save', function (next) {
    var that = this;
    that.allowed = that.allowed || {};
    permission.permit(that.allowed, 'users:' + that.user, 'read');
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

token.statics.refresh = function (id, done) {
    var Token = this;
    Lock.acquire('refresh-' + id, function (err, release) {
        if (err) {
            return done(err);
        }
        crypto.randomBytes(TOKEN_LENGTH, function (err, buf) {
            if (err) {
                release();
                return done(err);
            }
            Token.update({_id: id}, {
                access: buf.toString('hex'),
                created: Date.now()
            }, function (err) {
                release();
                done(err);
            });
        });
    });
};

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