/**
 * Module dependencies.
 */
var passport        = require('passport')
  , util            = require('util')
  , BadRequestError = require('./errors/badrequesterror')
  , oneid           = require('oneid');

var oneIDClient;

/**
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify  = options;
    options = {};
  }
  if (!verify) throw new Error('oneID authentication strategy requires a verify function');
  if (!options.apiID || !options.apiKey) throw new Error('Missing Keychain API Credentials. Please register at https://keychain.oneid.com/register');


  passport.Strategy.call(this);
  this.name               = 'oneid';
  this._verify            = verify;
  this._passReqToCallback = options.passReqToCallback;

  if (!oneIDClient) {
    oneIDClient = oneid.getClient(options.apiKey, options.apiID, options.server || '');
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var uid = req.body.uid;

  if (!uid) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing UID'));
  }

  var self = this;

  function verified(err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    self.success(user, info);
  }


  oneIDClient.validate(req.body, function (oneid_res) {
    console.log(req.body);
    if (oneid_res.isValid()) {
      if (self._passReqToCallback) {
        self._verify(req, uid, verified);
      } else {
        self._verify(uid, verified);
      }
    }
    else {
      self.fail(oneid_res);
    }
  });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
