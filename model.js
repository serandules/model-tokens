var log = require('logger')('model-tokens');
var mongoose = require('mongoose');
var autopopulate = require('mongoose-autopopulate');
var Schema = mongoose.Schema;
var crypto = require('crypto');
var async = require('async');
var _ = require('lodash');

var Lock = require('lock');
var mongins = require('mongins');
var types = require('validators').types;
var permission = require('permission');

var TOKEN_LENGTH = 48;

var accessibility = 60 * 1000;
var refreshability = 10 * accessibility;

var token = Schema({
    has: {
        type: Object,
        default: {
            '*': {
                '': ['*']
            }
        }
    },
    created: {type: Date, default: Date.now},
    access: String,
    accessible: {type: Number, default: accessibility},
    refresh: String,
    refreshable: {type: Number, default: refreshability},
    client: {
        type: Schema.Types.ObjectId,
        ref: 'clients',
        validator: types.ref(),
        autopopulate: true
    }
}, {collection: 'tokens'});

token.plugin(mongins);
token.plugin(mongins.user);
token.plugin(mongins.createdAt);
token.plugin(mongins.updatedAt);

token.plugin(autopopulate);

token.methods.accessibility = function () {
    var exin = this.created.getTime() + this.accessible - new Date().getTime();
    return exin > 0 ? exin : 0;
};

token.methods.refreshability = function () {
    var exin = this.created.getTime() + this.refreshable - new Date().getTime();
    return exin > 0 ? exin : 0;
};

token.methods.can = function (perm, action, o) {
    var permissions = o.permissions;
    if (!permissions) {
        return false;
    }
    var user = this.user;
    var entry = _.find(permissions, function (o) {
        return String(o.user) === user.id;
    });
    if (!entry) {
        return false;
    }
    var actions = entry.actions;
    if (actions.indexOf(action) === -1) {
        return false;
    }
    var trees = [this.has, this.client.has];
    return permission.every(trees, perm, action);
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

module.exports = mongoose.model('tokens', token);