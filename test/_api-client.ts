import uuid = require('uuid')
import srp = require('secure-remote-password/server')

import { Ephemeral } from 'secure-remote-password/server'

import ApiClient, { SignupInput, SubscriptionPlan, FinalizeLoginInput, AuthToken, ChangelogEntryInput, ChangelogEntryOutput, PaymentInformation, SubscriptionStatus } from '../src/api-client'
import HumanFormat from '../src/human-format'

class MockApiClient implements ApiClient {
  apiHost = ''
  deseatmeApiHost = ''

  private users: (SignupInput & { id: string, hasPaymentInformation: boolean, subscriptionStatus: SubscriptionStatus })[] = []
  private sessions: { [id: string]: { userId: string, serverEphemeral: Ephemeral } } = {}
  private changelogEntries: { [userId: string]: ChangelogEntryOutput[] } = {}

  async getSubscriptionPlans (): Promise<SubscriptionPlan[]> {
    return [{ id: 'test', amount: 299, currency: 'USD', interval: 'month', intervalCount: 1, stripeKey: 'x', trialPeriodDays: null }]
  }

  async signup (data: SignupInput) {
    const user = Object.assign({}, data, { id: uuid(), hasPaymentInformation: true, subscriptionStatus: 'trialing' as SubscriptionStatus })

    this.users.push(user)

    return { token: user.id }
  }

  async initiateLogin (handle: string) {
    const user = this.users.find(u => u.handle === handle)
    const serverEphemeral = srp.generateEphemeral(user.srpVerifier)
    const id = uuid()

    this.sessions[id] = { userId: user.id, serverEphemeral }

    return { id, serverPublicEphemeral: serverEphemeral.public, salt: user.srpSalt }
  }

  async finalizeLogin (loginSessionId: string, { clientPublicEphemeral, clientSessionProof }: FinalizeLoginInput) {
    const { userId, serverEphemeral } = this.sessions[loginSessionId]
    const { handle, dekSalt, srpSalt, srpVerifier, hasPaymentInformation, subscriptionStatus } = this.users.find(u => u.id === userId)

    const { proof } = srp.deriveSession(serverEphemeral, clientPublicEphemeral, srpSalt, HumanFormat.toHex(handle), srpVerifier, clientSessionProof)

    return { proof, token: userId, dekSalt, hasPaymentInformation, subscriptionStatus, trialDaysLeft: (subscriptionStatus === 'active' ? 0 : 7) }
  }

  async deleteUser (token: AuthToken) {
    const idx = this.users.findIndex(u => u.id === token)

    if (idx === -1) throw Object.assign(new Error('User not found'), { statusCode: 404 })

    this.users.splice(idx, 1)
  }

  async getChangelogEntries (token: AuthToken) {
    return (this.changelogEntries[token] || [])
  }

  async postChangelogEntry (token: AuthToken, data: ChangelogEntryInput) {
    if (!this.changelogEntries[token]) this.changelogEntries[token] = []

    const entry = Object.assign({}, data, { id: uuid(), createdAt: new Date().toISOString() })

    this.changelogEntries[token].push(entry)

    return entry
  }

  async setPaymentInformation (token: AuthToken, data: PaymentInformation) {
    this.users.find(u => u.id === token).hasPaymentInformation = true
    this.users.find(u => u.id === token).subscriptionStatus = 'active'

    return { hasPaymentInformation: true, subscriptionStatus: 'active' as SubscriptionStatus, trialDaysLeft: 0 }
  }

  async getDeseatmeExport (exportToken: string) {
    return { email: 'test@example.com', domains: ['a.deseat.me', 'b.deseat.me'] }
  }
}

export default MockApiClient
