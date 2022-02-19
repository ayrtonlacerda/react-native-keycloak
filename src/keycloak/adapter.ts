import type {
  CallbackStorage,
  FetchTokenResponse,
  KeycloakAdapter,
  KeycloakConfig,
  KeycloakInstance,
  KeycloakJSON,
  KeycloakLoginOptions,
  KeycloakLogoutOptions,
  KeycloakProfile,
  KeycloakRegisterOptions,
  OIDCProviderConfig,
} from '@react-keycloak/keycloak-ts';
import InAppBrowser from 'react-native-inappbrowser-reborn';

import LocalStorage from './storage';
import { Storage } from '../service';
import type { RNKeycloakInitOptions } from './types';
import { fetchJSON } from './utils';

class RNAdapter implements KeycloakAdapter {
  private readonly client: Readonly<KeycloakInstance>;
  private tokenStorage: any;
  private readonly initOptions: Readonly<RNKeycloakInitOptions>;

  constructor(
    client: Readonly<KeycloakInstance>,
    _keycloakConfig: Readonly<KeycloakConfig>,
    initOptions: Readonly<RNKeycloakInitOptions>
  ) {
    this.client = client;
    this.initOptions = initOptions;
    this.tokenStorage = new Storage();
  }

  createCallbackStorage(): CallbackStorage {
    return new LocalStorage();
  }

  /**
   * Start login process
   *
   * @param {KeycloakLoginOptions} options Login options
   */
  async login(options?: KeycloakLoginOptions): Promise<void> {
    const loginUrl = this.client.createLoginUrl(options);
    /**
     * Remover esse if por uma verificacao de token salvo.
     */
    const recuveredToken = await this.tokenStorage.recuverToken();
    if (recuveredToken) {
      const fakeValue = {
        state: 'fake',
        session_state: 'fake',
        code: 'fake',
        newUrl: 'fake',
        valid: true,
        redirectUri: 'fake',
        storedNonce: 'fake',
      };
      return this.client.processCallback(fakeValue);
    }
    if (await InAppBrowser.isAvailable()) {
      // See for more details https://github.com/proyecto26/react-native-inappbrowser#authentication-flow-using-deep-linking
      const res = await InAppBrowser.openAuth(
        loginUrl,
        this.client.redirectUri!,
        this.initOptions.inAppBrowserOptions
      );

      if (res.type === 'success' && res.url) {
        const oauth = this.client.parseCallback(res.url);
        return this.client.processCallback(oauth);
      }
      throw new Error('Authentication flow failed');
    } else {
      throw new Error('InAppBrowser not available');
      // TODO: maybe!
      //   Linking.openURL(loginURL);
    }
  }

  async logout(options?: KeycloakLogoutOptions): Promise<void> {
    const logoutUrl = this.client.createLogoutUrl(options);
    await this.tokenStorage.cleanToken();
    if (await InAppBrowser.isAvailable()) {
      // See for more details https://github.com/proyecto26/react-native-inappbrowser#authentication-flow-using-deep-linking
      const res = await InAppBrowser.openAuth(
        logoutUrl,
        this.client.redirectUri!,
        this.initOptions.inAppBrowserOptions
      );

      if (res.type === 'success') {
        return this.client.clearToken();
      }

      throw new Error('Logout flow failed');
    } else {
      throw new Error('InAppBrowser not available');
      // TODO: maybe!
      //   Linking.openURL(logoutUrl);
    }
  }

  async register(options?: KeycloakRegisterOptions) {
    const registerUrl = this.client.createRegisterUrl(options);

    if (await InAppBrowser.isAvailable()) {
      // See for more details https://github.com/proyecto26/react-native-inappbrowser#authentication-flow-using-deep-linking
      const res = await InAppBrowser.openAuth(
        registerUrl,
        this.client.redirectUri!,
        this.initOptions.inAppBrowserOptions
      );

      if (res.type === 'success' && res.url) {
        const oauth = this.client.parseCallback(res.url);
        return this.client.processCallback(oauth);
      }

      throw new Error('Registration flow failed');
    } else {
      throw new Error('InAppBrowser not available');
      // TODO: maybe!
      //   Linking.openURL(registerUrl);
    }
  }

  async accountManagement() {
    const accountUrl = this.client.createAccountUrl();

    if (typeof accountUrl !== 'undefined') {
      await InAppBrowser.open(accountUrl, this.initOptions.inAppBrowserOptions);
    } else {
      throw 'Not supported by the OIDC server';
    }
  }

  async fetchKeycloakConfigJSON(configUrl: string): Promise<KeycloakJSON> {
    return await fetchJSON<KeycloakJSON>(configUrl);
  }

  async fetchOIDCProviderConfigJSON(
    oidcProviderConfigUrl: string
  ): Promise<OIDCProviderConfig> {
    return await fetchJSON<OIDCProviderConfig>(oidcProviderConfigUrl);
  }

  async fetchTokens(
    tokenUrl: string,
    params: string
  ): Promise<FetchTokenResponse> {
    const recuveredToken = await this.tokenStorage.recuverToken();
    if (recuveredToken) {
      return await JSON.parse(recuveredToken);
    }
    const tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-type': 'application/x-www-form-urlencoded',
      },
      body: this.initOptions.clientSecret
        ? String(`${params}&client_secret=${this.initOptions.clientSecret}`)
        : params,
    });
    const response = (await tokenRes.json()) as FetchTokenResponse;
    if (response.access_token) {
      await this.tokenStorage.saveToken(response);
    }
    return response;
  }

  async refreshTokens(
    tokenUrl: string,
    params: string
  ): Promise<FetchTokenResponse> {
    const tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-type': 'application/x-www-form-urlencoded',
      },
      body: params,
    });
    return (await tokenRes.json()) as FetchTokenResponse;
  }

  async fetchUserProfile(
    profileUrl: string,
    token: string
  ): Promise<KeycloakProfile> {
    return await fetchJSON<KeycloakProfile>(profileUrl, token);
  }

  async fetchUserInfo(userInfoUrl: string, token: string): Promise<unknown> {
    return await fetchJSON<unknown>(userInfoUrl, token);
  }

  redirectUri(options?: { redirectUri?: string }): string {
    if (options && options.redirectUri) {
      return options.redirectUri;
    }

    if (this.client.redirectUri) {
      return this.client.redirectUri;
    }

    return ''; // TODO: Retrieve app deeplink
  }
}

export default RNAdapter;
