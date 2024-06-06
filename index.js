/**
 * Module dependencies.
 */

const InvalidArgumentError = require("@node-oauth/oauth2-server/lib/errors/invalid-argument-error");
const NodeOAuthServer = require("@node-oauth/oauth2-server");
const Request = require("@node-oauth/oauth2-server").Request;
const Response = require("@node-oauth/oauth2-server").Response;
const UnauthorizedRequestError = require("@node-oauth/oauth2-server/lib/errors/unauthorized-request-error");

/**
 * Complete, compliant and well tested express wrapper for @node-oauth/oauth2-server in node.js.
 * The module provides two middlewares - one for granting tokens and another to authorize them.
 * `@node-oauth/express-oauth-server` and, consequently `@node-oauth/oauth2-server`,
 * expect the request body to be parsed already.
 * The following example uses `body-parser` but you may opt for an alternative library.
 *
 * @class
 * @example
 * const bodyParser = require('body-parser');
 * const express = require('express');
 * const OAuthServer = require('@node-oauth/express-oauth-server');
 *
 * const app = express();
 *
 * app.oauth = new OAuthServer({
 *   model: {}, // See https://github.com/node-oauth/node-oauth2-server for specification
 * });
 *
 * app.use(bodyParser.json());
 * app.use(bodyParser.urlencoded({ extended: false }));
 * app.use(app.oauth.authorize());
 *
 * app.use(function(req, res) {
 *   res.send('Secret area');
 * });
 *
 * app.listen(3000);
 */
class ExpressOAuthServer {
  /**
   * Creates a new OAuth2 server that will be bound to this class' middlewares.
   * Constructor takes several options as arguments.
   * The following describes only options, specific to this module.
   * For all other options, please read the docs from `@node-oauth/oauth2-server`:
   * @see https://node-oauthoauth2-server.readthedocs.io/en/master/api/oauth2-server.html
   * @constructor
   * @param options {object=} optional options
   * @param options.useErrorHandler {boolean=} If false, an error response will be rendered by this component.
   *   Set this value to true to allow your own express error handler to handle the error.
   * @param options.continueMiddleware {boolean=} The `authorize()` and `token()` middlewares will both render their
   *   result to the response and end the pipeline.
   *   next() will only be called if this is set to true.
   *   **Note:** You cannot modify the response since the headers have already been sent.
   *   `authenticate()` does not modify the response and will always call next()
   */
  constructor(options = {}) {
    if (!options.model) {
      throw new InvalidArgumentError("Missing parameter: `model`");
    }

    this.useErrorHandler = !!options.useErrorHandler;
    delete options.useErrorHandler;

    this.continueMiddleware = !!options.continueMiddleware;
    delete options.continueMiddleware;

    this.server = new NodeOAuthServer(options);
  }

  /**
   * Authentication Middleware.
   * Returns a middleware that will validate a token.
   *
   * @param options {object=} will be passed to the authenticate-handler as options, see linked docs
   * @see https://node-oauthoauth2-server.readthedocs.io/en/master/api/oauth2-server.html#authenticate-request-response-options
   * @see: https://tools.ietf.org/html/rfc6749#section-7
   * @return {function(req, res, next):Promise.<Object>}
   */
  authenticate(options) {
    const fn = async function (req, res, next) {
      const request = new Request(req);
      const response = new Response(res);

      let token;

      try {
        token = await this.server.authenticate(request, response, options);
      } catch (e) {
        return handleError.call(this, e, req, res, null, next);
      }

      // Set header on express response
      res.set(response.headers);

      res.locals.oauth = { token };
      next();
    };

    return fn.bind(this);
  }

  /**
   * Authorization Middleware.
   * Returns a middleware that will authorize a client to request tokens.
   *
   * @param options {object=} will be passed to the authorize-handler as options, see linked docs
   * @see https://node-oauthoauth2-server.readthedocs.io/en/master/api/oauth2-server.html#authorize-request-response-options
   * @see: https://tools.ietf.org/html/rfc6749#section-3.1
   * @return {function(req, res, next):Promise.<Object>}
   */
  authorize(options) {
    const fn = async function (req, res, next) {
      const request = new Request(req);
      const response = new Response(res);

      let code;

      try {
        code = await this.server.authorize(request, response, options);
      } catch (e) {
        return handleError.call(this, e, req, res, response, next);
      }

      res.locals.oauth = { code };
      if (this.continueMiddleware) {
        next();
      }

      return handleResponse.call(this, req, res, response);
    };

    return fn.bind(this);
  }

  /**
   * Grant Middleware.
   * Returns middleware that will grant tokens to valid requests.
   *
   * @param options {object=} will be passed to the token-handler as options, see linked docs
   * @see https://node-oauthoauth2-server.readthedocs.io/en/master/api/oauth2-server.html#token-request-response-options
   * @see: https://tools.ietf.org/html/rfc6749#section-3.2
   * @return {function(req, res, next):Promise.<Object>}
   */
  token(options) {
    const fn = async function (req, res, next) {
      const request = new Request(req);
      const response = new Response(res);

      let token;

      try {
        token = await this.server.token(request, response, options);
      } catch (e) {
        return handleError.call(this, e, req, res, response, next);
      }

      res.locals.oauth = { token };
      if (this.continueMiddleware) {
        next();
      }

      return handleResponse.call(this, req, res, response);
    };

    return fn.bind(this);
  }
}

/**
 * Handle response.
 * @private
 */
const handleResponse = function (req, res, response) {
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
 * @private
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
 * @private
 */

module.exports = ExpressOAuthServer;
