import { applyPatch, Operation } from 'fast-json-patch'
import { FannyPack } from '@fanny-pack/core'
import hexToArrayBuffer = require('hex-to-array-buffer')
import randomAccountPassword = require('@ctrlpanel/random-account-password')
import srp = require('secure-remote-password/client')
import uuid = require('uuid')

import ApiClient, { FinalizeLoginResponse, LoginSession, PaymentInformation, SubscriptionPlan, SubscriptionStatus, DeseatmeExport } from './api-client'
import CtrlpanelCrypto, { DecryptedEntry } from './crypto'
import HumanFormat from './human-format'
import LocalStorage from './local-storage'

import randomHandle from './random-handle'
import randomMasterPassword from './random-master-password'
import randomSecretKey from './random-secret-key'

export { DecryptedEntry } from './crypto'
export { PaymentInformation, SubscriptionPlan, SubscriptionStatus } from './api-client'

function removeWhitespace (input: string) {
  return input.replace(/\s+/g, '')
}

function parseSyncToken (input: string) {
  return {
    handle: HumanFormat.dashify(input.substring(0, 26)),
    secretKey: HumanFormat.dashify(input.substring(26))
  }
}

function stringifySyncToken (handle: string, secretKey: string) {
  return `${handle}${secretKey}`.replace(/-/g, '')
}

export interface Account {
  handle: string
  hostname: string
  password: string
}

export interface InboxEntry {
  hostname: string
  email: string
}

export interface ParsedEntries {
  accounts: { [key: string]: Account }
  inbox: { [key: string]: InboxEntry }
}

export interface Options {
  apiHost?: string
  deseatmeApiHost?: string
  storage: FannyPack
  syncCredentialsToLocalStorage?: boolean
}

export interface EmptyState {
  kind: 'empty'
}

export interface LockedState {
  kind: 'locked'

  handle: string
  secretKey: string
}

export interface UnlockedState {
  kind: 'unlocked'

  dataEncryptionKey: CryptoKey
  decryptedEntries: DecryptedEntry[]
  handle: string
  secretKey: string
  srpPrivateKey: string
}

export interface ConnectedState {
  kind: 'connected'

  authToken: string
  dataEncryptionKey: CryptoKey
  decryptedEntries: DecryptedEntry[]
  handle: string
  secretKey: string
  srpPrivateKey: string
  hasPaymentInformation: boolean
  subscriptionStatus: SubscriptionStatus
  trialDaysLeft: number
}

export type State = EmptyState | LockedState | UnlockedState | ConnectedState

export default class CtrlpanelCore {
  /** Generate a random account password */
  static randomAccountPassword = randomAccountPassword

  /** Generate a random handle */
  static randomHandle = randomHandle

  /** Generate a random master password */
  static randomMasterPassword = randomMasterPassword

  /** Generate a random secret key */
  static randomSecretKey = randomSecretKey

  private apiClient: ApiClient
  private storage: LocalStorage

  constructor (options: Options) {
    const apiHost = options.apiHost ||'https://api.ctrlpanel.io'
    const deseatmeApiHost = options.deseatmeApiHost || 'https://api.deseat.me'
    const syncCredentialsToLocalStorage = options.syncCredentialsToLocalStorage || false

    this.apiClient = new ApiClient(apiHost, deseatmeApiHost)
    this.storage = new LocalStorage(options.storage, syncCredentialsToLocalStorage)
  }

  /** Construct the initial state */
  async init (syncToken?: string): Promise<EmptyState | LockedState> {
    const storedCredentials = await this.storage.readCredentials()
    const syncCredentials = syncToken && parseSyncToken(syncToken)

    if (storedCredentials && syncCredentials) {
      throw Object.assign(new Error('Tried to sync credentials to an already synced device'), { code: 'CONFLICTING_CREDENTIALS' })
    }

    if (syncCredentials) {
      await this.storage.writeCredentials(syncCredentials)
      return { kind: 'locked', ...syncCredentials }
    } else if (storedCredentials) {
      return { kind: 'locked', ...storedCredentials }
    } else {
      return { kind: 'empty' }
    }
  }

  /** Clear all stored data, and return an empty state */
  async clearStoredData (state: State): Promise<EmptyState> {
    await this.storage.clear()

    return { kind: 'empty' }
  }

  /** Delete the user with the api, then clear all stored data and return an empty state */
  async deleteUser (state: ConnectedState): Promise<EmptyState> {
    await this.apiClient.deleteUser(state.authToken)

    return this.clearStoredData(state)
  }

  /** Transition to the locked state */
  lock (state: UnlockedState | ConnectedState): LockedState {
    const { handle, secretKey } = state

    return { kind: 'locked', handle, secretKey }
  }

  /** Signup a new user with the api, then return a connected state */
  async signup (state: EmptyState, info: { email?: string, handle: string, secretKey: string, masterPassword: string, paymentInformation?: PaymentInformation }): Promise<ConnectedState> {
    // Generate salts
    const dekSalt = srp.generateSalt()
    const srpSalt = srp.generateSalt()

    // The user should be able to enter the password with or without spaces
    const cleanPassword = removeWhitespace(info.masterPassword)

    // Raw values
    const rawDekSalt = hexToArrayBuffer(dekSalt)
    const rawSrpSalt = hexToArrayBuffer(srpSalt)
    const rawHandle = HumanFormat.parse(info.handle)
    const rawSecretKey = HumanFormat.parse(info.secretKey)

    // Create user at the remote server
    const srpPrivateKey = await CtrlpanelCrypto.deriveSrpPrivateKey({ password: cleanPassword, salt: rawSrpSalt, handle: rawHandle, secretKey: rawSecretKey })
    const srpVerifier = srp.deriveVerifier(srpPrivateKey)
    const { token } = await this.apiClient.signup({ email: info.email, handle: info.handle, dekSalt, srpSalt, srpVerifier, paymentInformation: info.paymentInformation })

    // Derive data encryption key (DEK)
    const dataEncryptionKey = await CtrlpanelCrypto.deriveDataEncryptionKey({ password: cleanPassword, salt: rawDekSalt, handle: rawHandle, secretKey: rawSecretKey })

    // Store handle and secret key for automatic login
    await this.storage.writeCredentials({ handle: info.handle, secretKey: info.secretKey })

    // Store Fast Track information for login without online server
    const encryptedSrpPrivateKey = await CtrlpanelCrypto.encryptSrpPrivateKey(dataEncryptionKey, srpPrivateKey)
    await this.storage.writeFastTrack({ dekSalt, srpPrivateKey: encryptedSrpPrivateKey })

    return {
      kind: 'connected',

      authToken: token,
      dataEncryptionKey: dataEncryptionKey,
      decryptedEntries: [],
      handle: info.handle,
      secretKey: info.secretKey,
      srpPrivateKey: srpPrivateKey,
      hasPaymentInformation: false,
      subscriptionStatus: 'trialing',
      trialDaysLeft: 7,
    }
  }

  /** Login as an existing user with the api, then return a connected state */
  async login (state: EmptyState, info: { handle: string, secretKey: string, masterPassword: string }): Promise<ConnectedState> {
    // Generate ephemeral pair
    const ephemeral = srp.generateEphemeral()

    // Raw values
    const rawHandle = HumanFormat.parse(info.handle)
    const rawSecretKey = HumanFormat.parse(info.secretKey)

    let loginSession: LoginSession
    try {
      loginSession = await this.apiClient.initiateLogin(info.handle)
    } catch (err) {
      throw Object.assign(new Error('Failed to login'), { code: 'HANDLE_NOT_FOUND', originalError: err })
    }

    // The user should be able to enter the password with or without spaces
    const cleanPassword = removeWhitespace(info.masterPassword)

    const srpPrivateKey = await CtrlpanelCrypto.deriveSrpPrivateKey({ password: cleanPassword, salt: hexToArrayBuffer(loginSession.salt), handle: rawHandle, secretKey: rawSecretKey })
    const srpSession = srp.deriveSession(ephemeral, loginSession.serverPublicEphemeral, loginSession.salt, HumanFormat.toHex(info.handle), srpPrivateKey)

    let loginResult: FinalizeLoginResponse
    try {
      loginResult = await this.apiClient.finalizeLogin(loginSession.id, { clientPublicEphemeral: ephemeral.public, clientSessionProof: srpSession.proof })
    } catch (err) {
      throw Object.assign(new Error('Failed to login'), { code: 'WRONG_SECRET_KEY_OR_MASTER_PASSWORD', originalError: err })
    }

    srp.verifySession(ephemeral, srpSession, loginResult.proof)

    const dataEncryptionKeyPromise = CtrlpanelCrypto.deriveDataEncryptionKey({ password: cleanPassword, salt: hexToArrayBuffer(loginResult.dekSalt), handle: rawHandle, secretKey: rawSecretKey })

    // Store handle and secret key for automatic login
    await this.storage.writeCredentials({ handle: info.handle, secretKey: info.secretKey })

    // Store Fast Track information for login without online server
    const encryptedSrpPrivateKey = await CtrlpanelCrypto.encryptSrpPrivateKey(await dataEncryptionKeyPromise, srpPrivateKey)
    await this.storage.writeFastTrack({ dekSalt: loginResult.dekSalt, srpPrivateKey: encryptedSrpPrivateKey })

    return {
      kind: 'connected',

      authToken: loginResult.token,
      dataEncryptionKey: await dataEncryptionKeyPromise,
      decryptedEntries: [],
      handle: info.handle,
      secretKey: info.secretKey,
      srpPrivateKey: srpPrivateKey,
      hasPaymentInformation: loginResult.hasPaymentInformation,
      subscriptionStatus: loginResult.subscriptionStatus,
      trialDaysLeft: loginResult.trialDaysLeft,
    }
  }

  /**
   * Unlock a locked state using the master password.
   *
   * If fast track information is stored, it will not talk to the api and
   * return a unlocked state. Otherwise a login with the api will be performed
   * and a connected state will be returned.
   */
  async unlock (state: LockedState, info: { masterPassword: string }): Promise<UnlockedState | ConnectedState> {
    // Read credentials
    const { handle, secretKey } = state

    // Raw values
    const rawHandle = HumanFormat.parse(handle)
    const rawSecretKey = HumanFormat.parse(secretKey)

    // The user should be able to enter the password with or without spaces
    const cleanPassword = removeWhitespace(info.masterPassword)

    // Read possibly stored fast track data
    const fastTrack = await this.storage.readFastTrack()

    if (fastTrack) {
      const dataEncryptionKey = await CtrlpanelCrypto.deriveDataEncryptionKey({ password: cleanPassword, salt: hexToArrayBuffer(fastTrack.dekSalt), handle: rawHandle, secretKey: rawSecretKey })

      let srpPrivateKey: string
      try {
        srpPrivateKey = await CtrlpanelCrypto.decryptSrpPrivateKey(dataEncryptionKey, fastTrack.srpPrivateKey)
      } catch (err) {
        throw Object.assign(new Error('Failed to unlock'), { code: 'WRONG_MASTER_PASSWORD', originalError: err })
      }

      const encryptedEntries = await this.storage.getAllChangelogEntries()
      const decryptedEntries = await CtrlpanelCrypto.decryptEntries(dataEncryptionKey, encryptedEntries)

      return {
        kind: 'unlocked',

        dataEncryptionKey: dataEncryptionKey,
        decryptedEntries: decryptedEntries,
        handle: handle,
        secretKey: secretKey,
        srpPrivateKey: srpPrivateKey,
      }
    }

    const ephemeral = srp.generateEphemeral()
    const loginSession = await this.apiClient.initiateLogin(handle)
    const srpPrivateKey = await CtrlpanelCrypto.deriveSrpPrivateKey({ password: cleanPassword, salt: hexToArrayBuffer(loginSession.salt), handle: rawHandle, secretKey: rawSecretKey })

    const srpSession = srp.deriveSession(ephemeral, loginSession.serverPublicEphemeral, loginSession.salt, HumanFormat.toHex(handle), srpPrivateKey)

    let loginResult: FinalizeLoginResponse
    try {
      loginResult = await this.apiClient.finalizeLogin(loginSession.id, { clientPublicEphemeral: ephemeral.public, clientSessionProof: srpSession.proof })
    } catch (err) {
      throw Object.assign(new Error('Failed to unlock'), { code: 'WRONG_MASTER_PASSWORD', originalError: err })
    }

    srp.verifySession(ephemeral, srpSession, loginResult.proof)

    const dataEncryptionKey = await CtrlpanelCrypto.deriveDataEncryptionKey({ password: cleanPassword, salt: hexToArrayBuffer(loginResult.dekSalt), handle: rawHandle, secretKey: rawSecretKey })

    let decryptedEntries: DecryptedEntry[] = []

    /* Upgrade old users to Fast Track */
    const encryptedSrpPrivateKey = await CtrlpanelCrypto.encryptSrpPrivateKey(dataEncryptionKey, srpPrivateKey)
    await this.storage.writeFastTrack({ dekSalt: loginResult.dekSalt, srpPrivateKey: encryptedSrpPrivateKey })

    /* Read cached changelog entries */
    const encryptedEntries = await this.storage.getAllChangelogEntries()
    decryptedEntries = await CtrlpanelCrypto.decryptEntries(dataEncryptionKey, encryptedEntries)

    return {
      kind: 'connected',

      authToken: loginResult.token,
      dataEncryptionKey: dataEncryptionKey,
      decryptedEntries: decryptedEntries,
      handle: handle,
      secretKey: secretKey,
      srpPrivateKey: srpPrivateKey,
      hasPaymentInformation: loginResult.hasPaymentInformation,
      subscriptionStatus: loginResult.subscriptionStatus,
      trialDaysLeft: loginResult.trialDaysLeft,
    }
  }

  /** Aquire an access token from the api, then return a connected state */
  async connect (state: UnlockedState): Promise<ConnectedState> {
    const { dataEncryptionKey, decryptedEntries, handle, secretKey, srpPrivateKey } = state

    const ephemeral = srp.generateEphemeral()
    const loginSession = await this.apiClient.initiateLogin(handle)

    const srpSession = srp.deriveSession(ephemeral, loginSession.serverPublicEphemeral, loginSession.salt, HumanFormat.toHex(handle), srpPrivateKey)
    const loginResult = await this.apiClient.finalizeLogin(loginSession.id, { clientPublicEphemeral: ephemeral.public, clientSessionProof: srpSession.proof })

    srp.verifySession(ephemeral, srpSession, loginResult.proof)

    return {
      kind: 'connected',

      authToken: loginResult.token,
      dataEncryptionKey: dataEncryptionKey,
      decryptedEntries: decryptedEntries,
      handle: handle,
      secretKey: secretKey,
      srpPrivateKey: srpPrivateKey,
      hasPaymentInformation: loginResult.hasPaymentInformation,
      subscriptionStatus: loginResult.subscriptionStatus,
      trialDaysLeft: loginResult.trialDaysLeft,
    }
  }

  /**
   * Download changelog entries from the api.
   *
   * Returns a new connected state with updated `decryptedEntries`.
   */
  async sync (state: ConnectedState): Promise<ConnectedState> {
    const { authToken, dataEncryptionKey } = state

    const encryptedEntries = await this.apiClient.getChangelogEntries(state.authToken)

    await this.storage.putChangelogEntries(encryptedEntries)

    const decryptedEntries = await CtrlpanelCrypto.decryptEntries(dataEncryptionKey, encryptedEntries)

    return Object.assign({}, state, { decryptedEntries })
  }

  /**
   * Update the payment information with the api.
   *
   * Returns a new connected state with updated `subscriptionStatus` and `trialDaysLeft`.
   */
  async setPaymentInformation (state: ConnectedState, paymentInformation: PaymentInformation): Promise<ConnectedState> {
    const { authToken } = state

    const { hasPaymentInformation, subscriptionStatus, trialDaysLeft } = await this.apiClient.setPaymentInformation(authToken, paymentInformation)

    return Object.assign({}, state, { hasPaymentInformation, subscriptionStatus, trialDaysLeft })
  }

  /**
   * Return a `ParsedEntries` structure from a unlocked or connected state.
   *
   * Use this function to get the actual data: the accounts and the inbox.
   */
  getParsedEntries (state: UnlockedState | ConnectedState) {
    return applyPatch({ accounts: {}, inbox: {} }, state.decryptedEntries.map(entry => entry.patch)).newDocument as ParsedEntries
  }

  /** Create a sync token from any state that has a `handle` and `secretKey` */
  getSyncToken (state: LockedState | UnlockedState | ConnectedState) {
    return stringifySyncToken(state.handle, state.secretKey)
  }

  /** Get a list of subscription plans from the api */
  getSubscriptionPlans (withTrial: boolean = true): Promise<SubscriptionPlan[]> {
    return this.apiClient.getSubscriptionPlans(withTrial)
  }

  /** Create a new account */
  async createAccount (state: ConnectedState, id: string, account: Account) {
    return this.submitPatch(state, { op: 'add', path: `/accounts/${id}`, value: account })
  }

  /** Remove an account */
  async deleteAccount (state: ConnectedState, id: string) {
    return this.submitPatch(state, { op: 'remove', path: `/accounts/${id}` })
  }

  /** Update an account */
  async updateAccount (state: ConnectedState, id: string, account: Account) {
    return this.submitPatch(state, { op: 'replace', path: `/accounts/${id}`, value: account })
  }

  /** Create a new inbox entry */
  async createInboxEntry (state: ConnectedState, id: string, inboxEntry: InboxEntry) {
    return this.submitPatch(state, { op: 'add', path: `/inbox/${id}`, value: inboxEntry })
  }

  /** Remove an inbox entry */
  async deleteInboxEntry (state: ConnectedState, id: string) {
    return this.submitPatch(state, { op: 'remove', path: `/inbox/${id}` })
  }

  /**
   * Import domains from deseat.me into the inbox.
   *
   * This function will call the deseat.me api and fetch a list of exported domains, using the
   * provided export token. Each of those domains will then be added as an entry to the inbox.
   */
  async importFromDeseatme (state: ConnectedState, exportToken: string) {
    const data = await this.apiClient.getDeseatmeExport(exportToken)

    for (const domain of data.domains) {
      state = await this.createInboxEntry(state, uuid(), { hostname: domain, email: data.email })
    }

    return state
  }

  /**
   * Submit a patch as a changelog entry to the api.
   *
   * Returns a new connected state with updated `decryptedEntries`.
   */
  private async submitPatch (state: ConnectedState, patch: Operation): Promise<ConnectedState> {
    const { authToken, dataEncryptionKey, decryptedEntries } = state

    const payload = await CtrlpanelCrypto.encryptPatch(patch, dataEncryptionKey)
    const changelogEntry = await this.apiClient.postChangelogEntry(authToken, payload)

    await this.storage.putChangelogEntries([changelogEntry])

    return Object.assign({}, state, { decryptedEntries: [...decryptedEntries, { patch, ...payload }] })
  }
}
