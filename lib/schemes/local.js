import jwtDecode from 'jwt-decode';
import getProp from 'dotprop';

export default class LocalScheme {
  constructor(auth, options) {
    this.$auth = auth;
    this.name = options._name;
    this.refreshInterval = undefined;

    this.options = Object.assign({}, DEFAULTS, options);
  }

  _setToken(token) {
    if (this.options.globalToken) {
      // Set Authorization token for all axios requests
      this.$auth.ctx.app.$axios.setHeader(this.options.tokenName, token);
    }
  }

  _clearToken() {
    if (this.options.globalToken) {
      // Clear Authorization token for all axios requests
      this.$auth.ctx.app.$axios.setHeader(this.options.tokenName, false);
    }
  }

  _updateTokens(action, result) {
    let accessToken = getProp(
      result,
      this.options.endpoints[action].propertyName
    );

    // extract refresh token and set expiration
    if (this.options.refreshToken) {
      var refreshToken = getProp(
        result,
        this.options.endpoints[action].refreshTokenPropertyName
      );
      var tokenExpiration = getProp(
        result,
        this.options.endpoints[action].expiredAtPropertyName
      );
    }

    if (this.options.tokenRequired) {
      const token = this.options.tokenType
        ? this.options.tokenType + ' ' + accessToken
        : accessToken;

      // update access token
      this.$auth.setToken(this.name, token);
      this._setToken(token);

      // update refresh token and register refresh-logic with axios
      if (refreshToken !== undefined) {
        this.$auth.setRefreshToken(this.name, refreshToken);
        this.$auth.setExpiration(this.name, tokenExpiration * 1000);
      }
    }
  }

  _tokenRefresh(self) {
    clearTimeout(this.refreshInterval);
    const endpoint = this.options.buildRefreshTokenRequest(
      this.$auth.getRefreshToken(this.name)
    );
    return this.$auth
      .request(endpoint, this.options.endpoints.refresh)
      .then((response) => {
        this._updateTokens('refresh', response);
        this._scheduleTokenRefresh();
      })
      .catch(() => {
        this.logout();
      });
  }

  _scheduleTokenRefresh() {
    let self = this;
    let intervalDuration =
      (self.$auth.getExpiration(self.name) - Date.now()) * 0.75;
    if (isNaN(intervalDuration) || intervalDuration < 10000) {
      // in case you misconfigured refreshing this will save your auth-server from a self-induced DDoS-Attack
      intervalDuration = 10000;
    }
    this.refreshInterval = setTimeout(() => {
      self._tokenRefresh();
    }, intervalDuration);
  }

  mounted() {
    if (this.options.tokenRequired) {
      const token = this.$auth.syncToken(this.name);
      this._setToken(token);
      if (this.options.refreshToken) {
        const refreshToken = this.$auth.syncRefreshToken(this.name);
        const expiration = this.$auth.syncExpiration(this.name);
        if (refreshToken) {
          if (isNaN(expiration) || expiration - Date.now() < 60000) {
            this._tokenRefresh();
          } else {
            this._scheduleTokenRefresh();
          }
        }
      }
    }

    return this.$auth.fetchUserOnce();
  }

  async login(endpoint) {
    if (!this.options.endpoints.login) {
      return;
    }

    // Ditch any leftover local tokens before attempting to log in
    await this._logoutLocally();

    const result = await this.$auth.request(
      endpoint,
      this.options.endpoints.login
    );

    this._updateTokens('login', result);
    if (this.options.refreshToken) {
      this._scheduleTokenRefresh();
    }

    return this.fetchUser();
  }

  async fetchUser(endpoint) {
    // Decode token
    if (this.options.decodeJWT) {
      const user = jwtDecode(this.$auth.getToken(this.name));
      this.$auth.setUser(user);
      return;
    }

    // User endpoint is disabled.
    if (!this.options.endpoints.user) {
      this.$auth.setUser({});
      return;
    }

    // Token is required but not available
    if (this.options.tokenRequired && !this.$auth.getToken(this.name)) {
      return;
    }

    // Try to fetch user and then set
    const user = await this.$auth.requestWith(
      this.name,
      endpoint,
      this.options.endpoints.user
    );
    this.$auth.setUser(user);
  }

  async logout(endpoint) {
    // Only connect to logout endpoint if it's configured
    if (this.options.endpoints.logout) {
      await this.$auth
        .requestWith(this.name, endpoint, this.options.endpoints.logout)
        .catch(() => {});
    }

    // But logout locally regardless
    return this._logoutLocally();
  }

  async _logoutLocally() {
    if (this.options.tokenRequired) {
      this._clearToken();
    }
    clearTimeout(this.refreshInterval);

    return this.$auth.reset();
  }
}

const DEFAULTS = {
  buildRefreshTokenRequest: (refreshToken) => ({
    data: {
      refreshToken
    }
  }),
  refreshToken: false,
  tokenRequired: true,
  tokenType: 'Bearer',
  globalToken: true,
  tokenName: 'Authorization'
};
