'use strict';

/**
 * Module dependencies.
 */

const InvalidArgumentError = require('@node-oauth/oauth2-server/lib/errors/invalid-argument-error');
const NodeOAuthServer = require('@node-oauth/oauth2-server');
const Promise = require('bluebird');
const Request = require('@node-oauth/oauth2-server').Request;
const Response = require('@node-oauth/oauth2-server').Response;
const UnauthorizedRequestError = require('@node-oauth/oauth2-server/lib/errors/unauthorized-request-error');

/**
 * Constructor.
 */

function ExpressOAuthServer(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.useErrorHandler = options.useErrorHandler ? true : false;
  delete options.useErrorHandler;

  this.continueMiddleware = options.continueMiddleware ? true : false;
  delete options.continueMiddleware;

  this.server = new NodeOAuthServer(options);
}

/**
 * Authentication Middleware.
 *
 * Returns a middleware that will validate a token.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-7)
 */

ExpressOAuthServer.prototype.authenticate = function (options) {
  const that = this;

  return function (req, res, next) {
    const request = new Request(req);
    const response = new Response(res);
    return Promise.bind(that)
      .then(function () {
        return this.server.authenticate(request, response, options);
      })
      .tap(function (token) {
        res.locals.oauth = { token: token };
        next();
      })
      .catch(function (e) {
        return handleError.call(this, e, req, res, null, next);
      });
  };
};

/**
 * Authorization Middleware.
 *
 * Returns a middleware that will authorize a client to request tokens.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
 */

ExpressOAuthServer.prototype.authorize = function (options) {
  const that = this;

  return function (req, res, next) {
    const request = new Request(req);
    const response = new Response(res);

    return Promise.bind(that)
      .then(function () {
        return this.server.authorize(request, response, options);
      })
      .tap(function (code) {
        res.locals.oauth = { code: code };
        if (this.continueMiddleware) {
          next();
        }
      })
      .then(function () {
        return handleResponse.call(this, req, res, response);
      })
      .catch(function (e) {
        return handleError.call(this, e, req, res, response, next);
      });
  };
};

/**
 * Grant Middleware.
 *
 * Returns middleware that will grant tokens to valid requests.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
 */

ExpressOAuthServer.prototype.token = function (options) {
  const that = this;

  return function (req, res, next) {
    const request = new Request(req);
    const response = new Response(res);

    return Promise.bind(that)
      .then(function () {
        return this.server.token(request, response, options);
      })
      .tap(function (token) {
        res.locals.oauth = { token: token };
        if (this.continueMiddleware) {
          next();
        }
      })
      .then(function () {
        return handleResponse.call(this, req, res, response);
      })
      .catch(function (e) {
        return handleError.call(this, e, req, res, response, next);
      });
  };
};

/**
 * Handle response.
 */
const handleResponse = function (_req, res, response) {
  if (response.status === 302) {
    const location = response.headers.location;
    delete response.headers.location;
    res.set(response.headers);
    res.redirect(location);
  } else {
    res.set(response.headers);
    res.status(response.status).send(response.body);
  }
};

/**
 * Handle error.
 */

const handleError = function (e, req, res, response, next) {
  if (this.useErrorHandler === true) {
    next(e);
  } else {
    if (response) {
      res.set(response.headers);
    }

    res.status(e.code);

    if (e instanceof UnauthorizedRequestError) {
      return res.send();
    }

    res.send({ error: e.name, error_description: e.message });
  }
};

/**
 * Export constructor.
 */

module.exports = ExpressOAuthServer;
