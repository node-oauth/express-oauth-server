// Type definitions for @node-oauth/express-oauth-server 3.0.0
// Project: https://github.com/node-oauth/express-oauth-server
// Definitions by: Arne Schubert <https://github.com/atd-schubert>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 2.3

import * as koa from 'koa';
import * as OAuth2Server from "@node-oauth/oauth2-server";

declare namespace KoaOAuthServer {
  interface Options extends OAuth2Server.ServerOptions {
    useErrorHandler?: boolean | undefined;
    continueMiddleware?: boolean | undefined;
  }
}

declare class KoaOAuthServer {
  server: OAuth2Server;

  constructor(options: KoaOAuthServer.Options);

  authenticate(
    options?: OAuth2Server.AuthenticateOptions
  ): (
    ctx: koa.ParameterizedContext,
    next: koa.Next,
  ) => Promise<void>;

  authorize(
    options?: OAuth2Server.AuthorizeOptions
  ): (
    ctx: koa.ParameterizedContext,
    next: koa.Next,
  ) => Promise<void>;

  token(
    options?: OAuth2Server.TokenOptions
  ): (
    ctx: koa.ParameterizedContext,
    next: koa.Next,
  ) => Promise<void>;
}

export = KoaOAuthServer;
