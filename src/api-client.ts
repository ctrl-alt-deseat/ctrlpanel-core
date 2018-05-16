/* global fetch, Headers */

export type AuthToken = string
export type SubscriptionStatus = 'trialing' | 'active' | 'past_due' | 'canceled' | 'unpaid'

import HumanFormat from './human-format'

export interface SubscriptionPlan {
  amount: number
  currency: string
  id: string
  interval: 'day' | 'week' | 'month' | 'year'
  intervalCount: number
  stripeKey: string
  trialPeriodDays: number
}

export interface SignupInput {
  handle: string
  dekSalt: string
  srpSalt: string
  srpVerifier: string
}

export interface SignupResponse {
  token: AuthToken
}

export interface LoginSession {
  id: string
  serverPublicEphemeral: string
  salt: string
}

export interface FinalizeLoginInput {
  clientPublicEphemeral: string
  clientSessionProof: string
}

export interface FinalizeLoginResponse {
  proof: string
  token: string
  dekSalt: string
  hasPaymentInformation: boolean
  subscriptionStatus: SubscriptionStatus
  trialDaysLeft: number
}

export interface ChangelogEntryInput {
  nonce: string
  encryptedPatch: string
}

export interface ChangelogEntryOutput {
  id: string
  nonce: string
  encryptedPatch: string
  createdAt: string
}

export interface ApplePaymentInformation {
  type: 'apple'
  transactionIdentifier: string
}

export interface StripePaymentInformation {
  type?: 'stripe'
  plan: string
  token: string
  email: string
  coupon?: string | null
}

export type PaymentInformation = ApplePaymentInformation | StripePaymentInformation

export interface PaymentInformationOutput {
  hasPaymentInformation: boolean
  subscriptionStatus: SubscriptionStatus
  trialDaysLeft: number
}

export interface DeseatmeExport {
  email: string
  domains: string[]
}

function parseResponse (response: Response) {
  if (response.status === 204) return Promise.resolve(undefined)
  if (response.ok) return response.json()

  return response.text().then(text => { throw new Error(text) })
}

function request<T> (input: RequestInfo, init?: RequestInit): Promise<T> {
  return fetch(input, init).then(parseResponse) as Promise<T>
}

class ApiClient {
  readonly apiHost: string
  readonly deseatmeApiHost: string

  constructor (apiHost: string, deseatmeApiHost: string) {
    this.apiHost = apiHost
    this.deseatmeApiHost = deseatmeApiHost
  }

  async getSubscriptionPlans () {
    const headers = new Headers({ 'Accept': 'application/json' })

    return request<SubscriptionPlan[]>(`${this.apiHost}/v1/subscription-plans`, { headers })
  }

  async signup ({ handle, dekSalt, srpSalt, srpVerifier }: SignupInput) {
    const method = 'POST'
    const body = JSON.stringify({ handle: HumanFormat.toHex(handle), dekSalt, srpSalt, srpVerifier })
    const headers = new Headers({ 'Accept': 'application/json', 'Content-Type': 'application/json' })

    return request<SignupResponse>(`${this.apiHost}/v1/users`, { method, body, headers })
  }

  async initiateLogin (handle: string) {
    const method = 'POST'
    const body = JSON.stringify({ handle: HumanFormat.toHex(handle) })
    const headers = new Headers({ 'Accept': 'application/json', 'Content-Type': 'application/json' })

    return request<LoginSession>(`${this.apiHost}/v1/login-sessions`, { method, headers, body })
  }

  async finalizeLogin (loginSessionId: string, data: FinalizeLoginInput) {
    const method = 'POST'
    const body = JSON.stringify(data)
    const headers = new Headers({ 'Accept': 'application/json', 'Content-Type': 'application/json' })

    return request<FinalizeLoginResponse>(`${this.apiHost}/v1/login-sessions/${loginSessionId}/finalize`, { method, headers, body })
  }

  async deleteUser (token: AuthToken) {
    const method = 'DELETE'
    const headers = new Headers({ 'Accept': 'application/json', 'Authorization': `Bearer ${token}` })

    return request<void>(`${this.apiHost}/v1/users/me`, { method, headers })
  }

  async getChangelogEntries (token: AuthToken) {
    const headers = new Headers({ 'Authorization': `Bearer ${token}` })

    return request<ChangelogEntryOutput[]>(`${this.apiHost}/v1/changelog-entries`, { headers })
  }

  async postChangelogEntry (token: AuthToken, data: ChangelogEntryInput) {
    const method = 'POST'
    const body = JSON.stringify(data)
    const headers = new Headers({ 'Accept': 'application/json', 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' })

    return request<ChangelogEntryOutput>(`${this.apiHost}/v1/changelog-entries`, { method, headers, body })
  }

  async setPaymentInformation (token: AuthToken, data: PaymentInformation) {
    const method = 'PUT'
    const body = JSON.stringify(data)
    const headers = new Headers({ 'Accept': 'application/json', 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' })

    return request<PaymentInformationOutput>(`${this.apiHost}/v1/payment-information`, { method, headers, body })
  }

  async getDeseatmeExport (exportToken: string) {
    const headers = new Headers({ 'Accept': 'application/json' })

    return request<DeseatmeExport>(`${this.deseatmeApiHost}/v1/export/${exportToken}`, { headers })
  }
}

export default ApiClient
