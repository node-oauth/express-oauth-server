/**
 * Module dependencies.
 */

const ExpressOAuthServer = require('../../');
const InvalidArgumentError = require('@node-oauth/oauth2-server/lib/errors/invalid-argument-error');
const UnauthorizedRequestError = require('@node-oauth/oauth2-server/lib/errors/unauthorized-request-error');
const NodeOAuthServer = require('@node-oauth/oauth2-server');
const bodyparser = require('body-parser');
const express = require('express');
const request = require('supertest');
const should = require('should');
const sinon = require('sinon');

/**
 * Test `ExpressOAuthServer`.
 */

describe('ExpressOAuthServer', function() {
  let app;

  beforeEach(function() {
    app = express();

    app.use(bodyparser.json());
    app.use(bodyparser.urlencoded({ extended: false }));
  });

  describe('constructor()', function() {
    it('should throw an error if `model` is missing', function() {
      try {
        new ExpressOAuthServer();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should set the `server`', function() {
      const oauth = new ExpressOAuthServer({ model: {} });
      oauth.server.should.be.an.instanceOf(NodeOAuthServer);
    });
  });

  describe('authenticate()', function() {
    it('should return an error if `model` is empty', function(done) {
      const oauth = new ExpressOAuthServer({ model: {} });
      app.use(oauth.authenticate());
      request(app.listen())
        .get('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getAccessToken()`' })
        .end(done);
    });

    it('should authenticate the request', function(done) {
      const tokenExpires = new Date();
      tokenExpires.setDate(tokenExpires.getDate() + 1);

      const token = { user: {}, accessTokenExpiresAt: tokenExpires };
      const model = {
        getAccessToken: function() {
          return token;
        }
      };
      const oauth = new ExpressOAuthServer({ model });

      app.use(oauth.authenticate());

      app.use(function(req, res, next) {
        res.send();

        next();
      });

      request(app.listen())
        .get('/')
        .set('Authorization', 'Bearer foobar')
        .expect(200)
        .end(done);
    });

    it('should return opaque error if the request lacks proper authentication', function(done) {
      const model = {
        getAccessToken: function() {
          throw new UnauthorizedRequestError();
        }
      };
      const oauth = new ExpressOAuthServer({ model });
      app.use(oauth.authenticate());

      request(app.listen())
        .get('/')
        .set('Authorization', 'Bearer foobar')
        .expect(401, function (err, res) {
          (err === null).should.eql(true);
          (res.body.error === undefined).should.eql(true);
          done();
        });
    });

    it('should cache the authorization token', function(done) {
      const tokenExpires = new Date();
      tokenExpires.setDate(tokenExpires.getDate() + 1);
      const token = { user: {}, accessTokenExpiresAt: tokenExpires };
      const model = {
        getAccessToken: function() {
          return token;
        }
      };
      const oauth = new ExpressOAuthServer({ model });

      app.use(oauth.authenticate());
      
      const spy = sinon.spy(function(req, res, next) {
        res.locals.oauth.token.should.equal(token);
        res.send(token);
        next();
      });
      app.use(spy);

      request(app.listen())
        .get('/')
        .set('Authorization', 'Bearer foobar')
        .expect(200, function(err /*, res */){
            spy.called.should.be.True();
            done(err);
        });
    });
  });

  describe('authorize()', function() {
    it('should cache the authorization code', function(done) {
      const tokenExpires = new Date();
      tokenExpires.setDate(tokenExpires.getDate() + 1);

      const code = { authorizationCode: 123 };
      const model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: tokenExpires };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return code;
        }
      };
      const oauth = new ExpressOAuthServer({ model, continueMiddleware: true });

      app.use(oauth.authorize());

      const spy = sinon.spy(function(req, res, next) {
        res.locals.oauth.code.should.equal(code);
        next();
      });
      app.use(spy);

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send({ client_id: 12345, response_type: 'code' })
        .expect(302, function(err /*, res */){
            spy.called.should.be.True();
            done(err);
        });
    });

    it('should return an error', function(done) {
      const model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: new Date() };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return {};
        }
      };
      const oauth = new ExpressOAuthServer({ model });

      app.use(oauth.authorize());

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send({ client_id: 12345 })
        .expect(400, function(err, res) {
          res.body.error.should.eql('invalid_request');
          res.body.error_description.should.eql('Missing parameter: `response_type`');
          done(err);
        });
    });

    it('should return a `location` header with the code', function(done) {
      const model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: new Date() };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return { authorizationCode: 123 };
        }
      };
      const oauth = new ExpressOAuthServer({ model });

      app.use(oauth.authorize());

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send({ client_id: 12345, response_type: 'code' })
        .expect('location', 'http://example.com/?code=123&state=foobiz')
        .end(done);
    });

    it('should use error handler', function(done) {
      const model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: new Date() };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return {};
        }
      };
      const oauth = new ExpressOAuthServer({ model, useErrorHandler: true });

      app.use(oauth.authorize());
      app.use(function (err, req, res, next) {
        err.status.should.eql(400);
        err.name.should.eql('invalid_request');
        err.message.should.eql('Missing parameter: `response_type`');
        (typeof next === 'function').should.eql(true);
        done();
      });

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send({ client_id: 12345 })
        .expect(500, function(err, res) {
          (err === null).should.eql(true);
          (res.body.error === undefined).should.eql(true);
        });
    });
    
    it('should return an error if `model` is empty', function(done) {
      const oauth = new ExpressOAuthServer({ model: {} });

      app.use(oauth.authorize());

      request(app)
        .post('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' })
        .end(done);
    });
  });

  describe('token()', function() {
    it('should cache the authorization token', function(done) {
      const token = { accessToken: 'foobar', client: {}, user: {} };
      const model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return token;
        }
      };
      const oauth = new ExpressOAuthServer({ model, continueMiddleware: true });

      app.use(oauth.token());
      const spy = sinon.spy(function(req, res, next) {
        res.locals.oauth.token.should.equal(token);

        next();
      });
      app.use(spy);

      request(app.listen())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', token_type: 'Bearer' })
        .expect(200, function(err /*, res */){
          spy.called.should.be.True();
          done(err);
        });
    });

    it('should return an `access_token`', function(done) {
      const model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return { accessToken: 'foobar', client: {}, user: {} };
        }
      };
      sinon.spy();
      const oauth = new ExpressOAuthServer({ model, continueMiddleware: true });

      app.use(oauth.token());
      request(app.listen())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', token_type: 'Bearer' })
        .end(done);
    });

    it('should return a `refresh_token`', function(done) {
      const model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return { accessToken: 'foobar', client: {}, refreshToken: 'foobiz', user: {} };
        }
      };
      const oauth = new ExpressOAuthServer({ model });

      app.use(oauth.token());

      request(app.listen())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', refresh_token: 'foobiz', token_type: 'Bearer' })
        .end(done);
    });

    it('should return an error if `model` is empty', function(done) {
      const oauth = new ExpressOAuthServer({ model: {} });

      app.use(oauth.token())

      request(app.listen())
        .post('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' })
        .end(done);
    });
  });
});
