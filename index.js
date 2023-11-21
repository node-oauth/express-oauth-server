/**
 * Module dependencies.
 */
const NodeOAuthServer = require('@node-oauth/oauth2-server');
const { Request, Response } = require('@node-oauth/oauth2-server');
const InvalidArgumentError = require('@node-oauth/oauth2-server/lib/errors/invalid-argument-error');
const UnauthorizedRequestError = require('@node-oauth/oauth2-server/lib/errors/unauthorized-request-error');

class KoaOAuthServer {
  constructor(options) {
    this.options = options || {};

    if (!this.options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }
    this.useErrorHandler = this.options.useErrorHandler === true;
    this.continueMiddleware = this.options.continueMiddleware === true;

    delete this.options.useErrorHandler;
    delete this.options.continueMiddleware;

    this.server = new NodeOAuthServer(this.options);
  }

  /**
   * Authentication Middleware.
   *
   * @param {*} options 
   * @returns {(ctx: import('koa').ParameterizedContext, next: import('koa').Next) => Promise<void>} A middleware that will validate a token.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-7)
   */
  authenticate(options) {
    return async (ctx, next) => {
      const request = new Request(ctx.request);
      const response = new Response(ctx.response);
      let token;
      try {
        token = await this.server.authenticate(request, response, options);
      } catch (err) {
        await this._handleError(ctx, null, err, next);
        return;
      }
      ctx.state.oauth = { token };
      await next();
    }
  }

  /**
   * Authorization Middleware.
   *
   * @param {*} options
   * @returns {(ctx: import('koa').ParameterizedContext, next: import('koa').Next) => Promise<void>} A middleware that will authorize a client to request tokens.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
   
   */
  authorize(options) {
    return async (ctx, next) => {
      const request = new Request(ctx.request);
      const response = new Response(ctx.response);
      let code;
      try {
        code = await this.server.authorize(request, response, options);
      } catch (err) {
        await this._handleError(ctx, response, err, next);
        return;
      }
      ctx.state.oauth = { code };
      if (this.continueMiddleware) {
        await next();
      }
      this._handleResponse(ctx, response);
    }
  }


  /**
   * Authorization Middleware.
   *
   * @param {*} options 
   * @returns {(ctx: import('koa').ParameterizedContext, next: import('koa').Next) => Promise<void>} A middleware that will authorize a client to request tokens.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
   */
  token(options) {
    return async (ctx, next) => {
      const request = new Request(ctx.request);
      const response = new Response(ctx.response);
      let token;
      try {
        token = await this.server.token(request, response, options);
      } catch (err) {
        await this._handleError(ctx, response, err, next);
        return;
      }
      ctx.state.oauth = { token };
      if (this.continueMiddleware) {
        await next();
      }
      this._handleResponse(ctx, response);
    }
  }

  /**
   * Grant Middleware.
   *
   * @param {import('koa').ParameterizedContext} ctx 
   * @param {*} oauthResponse 
   * @returns Middleware that will grant tokens to valid requests.
   *
   * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
   */
  _handleResponse(ctx, oauthResponse) {
    const location = oauthResponse.headers.location;
    if (oauthResponse.status === 302) {
      delete oauthResponse.headers.location;
    }
    ctx.set(oauthResponse.headers)
    if (oauthResponse.status === 302) {
      ctx.redirect(location);
    } else {
      ctx.status = oauthResponse.status;
      ctx.body = oauthResponse.body;
    }
  }

  /**
   * Handles errors depending on the options of `this.useErrorHandler`.
   * Either calls `next()` with the error (so the application can handle it), or returns immediately a response with the error.
   * @param {import('koa').ParameterizedContext} ctx 
   * @param {*} oauthResponse 
   * @param {*} error 
   * @param {import('koa').Next} next 
   * @returns 
   */
  async _handleError(ctx, oauthResponse, error, next) {
    if (this.useErrorHandler) {
      await next();
      return;
    }

    if (oauthResponse) {
      ctx.set(oauthResponse.headers)
    }

    ctx.status = error.code || 500;

    if (error instanceof UnauthorizedRequestError) {
      return;
    }

    ctx.body = { error: error.name, error_description: error.message };
  }
}


module.exports = KoaOAuthServer;
