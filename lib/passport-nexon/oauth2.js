"use strict";

/**
 * Passport wrapper for ldapauth
 */
var querystring= require('querystring')
  , passport = require('passport')
  , util = require('util')
  , OAuth2 = require('oauth').OAuth2
  , InternalOAuthError = require('../errors/internaloautherror');

/**
 * Strategy constructor
 *
 * The LDAP authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 * *
 * Options:
 * - `ticketField`  field name where the username is found, defaults to _username_
 * - `usernameField`  field name where the username is found, defaults to _username_
 * - `passwordField`  field name where the password is found, defaults to _password_
 * - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Example:
 *
 *     var NexonOAuth2Strategy = require('passport-nexon').OAuth2Strategy;
 *     passport.use(new NexonOAuth2Strategy({
 *         authorizationURL: 'https://accounts.nexon.net/auth/login',
 *         tokenURL: 'https://api.nexon.net/auth/token',
 *         userProfileURL: 'https://api.nexon.net/users/me/profile'
 *         productID: '10000',
 *         clientSecret: 'secret key',
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *         ticketField: 'ticket'  // optional
 *         ticketURL: 'https://api.nexon.net/auth/ticket'
 *         getTicketProcess: function(callback(err, ticket))
 *       },
 *       function(user, done) {
 *         return cb(null, user);
 *       }
 *     ));
 */
var Strategy = function(options, verify) {
  if (typeof options === 'function') {
    verify  = options;
    options = undefined;
  }

  if (!options) throw new Error('LDAP authentication strategy requires options');

  if (!options.authorizationURL) throw new Error('OAuth2Strategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OAuthStrategy requires a tokenURL option');
  if (!options.productID) throw new Error('OAuth2Strategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OAuth2Strategy requires a clientSecret option');

  passport.Strategy.call(this);

  //console.log('nexon init -----> ', options);

  this.name    = 'nexon';
  this.options = options;
  this._verify  = verify;

  this._oauth2 = new OAuth2(options.productID,  options.clientSecret,
      '', options.authorizationURL, options.tokenURL);

  this.options.usernameField || (this.options.usernameField = 'username');
  this.options.passwordField || (this.options.passwordField = 'password');
  this.options.ticketField || (this.options.ticketField = 'ticket');

  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
};

util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate the request coming from a form or such.
 */
Strategy.prototype.authenticate = function(req, options) {  
  options || (options = {});
  //console.log('here -----> ', options);
  var lookup = function (obj, field) {
    var i, len, chain, prop;
    if (!obj) { return null; }
    chain = field.split(']').join('').split('[');
    for (i = 0, len = chain.length; i < len; i++) {
      prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  };

  var self = this;
  var ticket = lookup(req.body, this.options.ticketField) || lookup(req.query, this.options.ticketField);

  if(ticket) {
    this.getSessionWithTicket(req, ticket);
  }
  else {
    //console.log('callbackURL -----> %s', this.options.callbackURL);
    if(this.options.callbackURL) { // use OAuth login 
      var params = {};
      params.prod_id = this.options.productID;    
      params.redirect_uri = this.options.callbackURL;
      var scope = options.scope || this.options.scope;
      if (scope) {
        if (Array.isArray(scope)) { scope = scope.join(this.options.scopeSeparator); }
        params.scope = scope;
      }
      var state = options.state || this.options.state;
      if (state) {
        params.state = state;
      }
      
      var location = this._oauth2.getAuthorizeUrl(params);
      //console.log('location -----> %s', location);

      this.redirect(location);
    }
    else if(this.options.getTicketProcess && typeof this.options.getTicketProcess === 'function') {
      this.options.getTicketProcess(function(err, ticket) {
        self.getSessionWithTicket(req, ticket);
      });
    }
    else {
      // login form
      var username, password;
      username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
      password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);
      if (!username || !password) return this.fail('Missing credentials');

      this._getTicket(username, password, function(err, ticket, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }
        else {
          self.getSessionWithTicket(req, ticket);
        }
      });
    }
  }
};

Strategy.prototype.getSessionWithTicket = function(req, ticket) {
  var self = this;
  this._getToken(ticket, function(err, accessToken, refreshToken, params) {
    if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }
    
    self._loadUserProfile(accessToken, function(err, profile) {
      if (err) { return self.error(err); };
      
      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }
      
      if (self.options.passReqToCallback) {
        var arity = self._verify.length;
        if (arity == 6) {
          self._verify(req, accessToken, refreshToken, params, profile, verified);
        } else { // arity == 5
          self._verify(req, accessToken, refreshToken, profile, verified);
        }
      } else {
        var arity = self._verify.length;
        if (arity == 5) {
          self._verify(accessToken, refreshToken, params, profile, verified);
        } else { // arity == 4
          self._verify(accessToken, refreshToken, profile, verified);
        }
      }
    });
  });
};

Strategy.prototype._getTicket = function(username, password, callback) {
    var post_data = {
      'user_id': username,
      'user_pw': password,
      'product_id': this.options.productID
    };

  this._oauth2._request('POST'
    , this.options.ticketURL
    , {'Content-Type': 'application/x-www-form-urlencoded'}
    , querystring.stringify(post_data)
    , null
    , function(err, data, response) {
      if (err) callback(err);
      else {      
        var results = JSON.parse(data);
        var ticket = results["ticket"];;
        callback(null, ticket, results);
      }
    });
};

Strategy.prototype._getToken = function(ticket, callback) {
  //console.log('ticket ---> %s', ticket);
  var post_data = {
    'ticket': ticket,
    'secret_key': this.options.clientSecret,
    'product_id': this.options.productID
  };
  this._oauth2._request('POST'
    , this.options.tokenURL
    , {'Content-Type': 'application/x-www-form-urlencoded'}
    , querystring.stringify(post_data)
    , null
    , function(err, data, response) {
      if (err) callback(err);
      else {      
        var results = JSON.parse(data);
        var access_token = results["token"];
        var refresh_token = results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results);
      }
    });
};

Strategy.prototype._loadUserProfile = function(accessToken, done) {
  var self = this;
  
  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }
  
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
}

Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this.options.userProfileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'nexon' };
      profile.id = json.user_no;
      profile.displayName = json.profile_name;

      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


module.exports = Strategy;
