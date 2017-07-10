'use strict';

/**
 * Module dependencies.
 */

var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var is = require('../validator/is');
var util = require('util');

/**
 * Constructor.
 */

function PasswordGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUser) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getUser()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(PasswordGrantType, AbstractGrantType);

/**
 * Retrieve the user from the model using a username/password combination.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
 */

PasswordGrantType.prototype.handle = function(request, client) {
  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  var scope = this.getScope(request);

  return Promise.bind(this)
    .then(function() {
      return this.getUser(request); /* match username: password */
    })
    .then(function(user) {
      return this.saveToken(user, client, scope);  /* return {access_token, expirty, userClaims } to token-handler next chain*/
    });
};

/**
 * Get user using a username/password combination.
 */

PasswordGrantType.prototype.getUser = function(request) {
  if (!request.body.username) {
    throw new InvalidRequestError('Missing parameter: `username`');
  }

  if (!request.body.password) {
    throw new InvalidRequestError('Missing parameter: `password`');
  }

  if (!is.uchar(request.body.username)) {
    throw new InvalidRequestError('Invalid parameter: `username`');
  }

  if (!is.uchar(request.body.password)) {
    throw new InvalidRequestError('Invalid parameter: `password`');
  }

  return promisify(this.model.getUser, 2)(request.body.username, request.body.password)
    .then(function(user) {
      if (!user) {
        throw new InvalidGrantError('Invalid grant: user credentials are invalid');
      }

      return user;
    });
};

/**
 * Save token into memory; so that we can validate the token once receiving it from client; !bchen
 */

PasswordGrantType.prototype.saveToken = function(user, client, scope) {
  var fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope), //step 1: create an random sha1 hash of a radom bytes[256] and use it as access_token;
    this.generateRefreshToken(client, user, scope),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(scope, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt) {
      var token /*step2: build a token object in clear text*/= {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        refreshToken: refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt,
        scope: scope
      };

      return promisify(this.model.saveToken /* for server to establish ** a relationship, i.e. a map** between 1. randomly generated sha1 hash and 2. client 3. user
                                              the object returned here is passed to next promse chain (seetokenHandler.tap) 
                                              which will send everything into client browser
                                              next time when client browser submits a random sh1 hash, we know what it stands for and how long it is valid;
       */, 3)(token, client, user);
    });
};

/**
 * Export constructor.
 */

module.exports = PasswordGrantType;
