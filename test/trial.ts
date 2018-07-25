import assert = require('assert')
import FannyPackMemory = require('@fanny-pack/memory')

import MockApiClient from './_api-client'

import Core, { State } from '../src/core'

describe('Trial', () => {
  let core: Core
  let state: State

  before(async () => {
    core = Object.assign(new Core({ storage: new FannyPackMemory() }), { apiClient: new MockApiClient() })
    state = await core.init()
  })

  it('lists subscription plans', async function () {
    const list = await core.getSubscriptionPlans()

    for (const plan of list) {
      assert.strictEqual(typeof plan.id, 'string')
      assert.strictEqual(typeof plan.amount, 'number')
      assert.strictEqual(typeof plan.currency, 'string')
      assert.strictEqual(typeof plan.interval, 'string')
      assert.strictEqual(typeof plan.intervalCount, 'number')
      assert.strictEqual(typeof plan.stripeKey, 'string')
      assert.strictEqual(plan.trialPeriodDays, null)
    }
  })

  it('starts with a seven day trial', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    const handle = Core.randomHandle()
    const secretKey = Core.randomSecretKey()
    const masterPassword = Core.randomMasterPassword()

    state = await core.signup(state, { handle, secretKey, masterPassword })

    assert.strictEqual(state.kind, 'connected')
    assert.strictEqual(state.subscriptionStatus, 'trialing')
    assert.strictEqual(state.trialDaysLeft, 7)
  })

  it('goes active when providing payment details', async function () {
    if (state.kind !== 'connected') throw new Error('Expected a connected state')

    state = await core.setPaymentInformation(state, { plan: 'x', token: 'x', email: 'linus@example.com' })

    assert.strictEqual(state.kind, 'connected')
    assert.strictEqual(state.subscriptionStatus, 'active')
    assert.strictEqual(state.trialDaysLeft, 0)
  })
})
