import _ = require('./_shims')

import assert = require('assert')

import MockApiClient from './_api-client'
import MockStorage from './_storage'

import Core, { State } from '../src/core'

describe('Login', () => {
  let core: Core
  let state: State

  const handle = Core.randomHandle()
  const secretKey = Core.randomSecretKey()
  const masterPassword = Core.randomMasterPassword()

  before(() => {
    core = Object.assign(new Core(), {
      apiClient: new MockApiClient(),
      storage: new MockStorage(),
    })

    state = core.init()
  })

  before('signup', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    await core.signup(state, handle, secretKey, masterPassword, false)
  })

  it('performs a login against the api', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    state = await core.login(state, handle, secretKey, masterPassword, false)

    assert.ok(state.authToken)
    assert.strictEqual(state.decryptedEntries.length, 0)
    assert.strictEqual(state.handle, handle)
    assert.strictEqual(state.kind, 'connected')
    assert.strictEqual(state.secretKey, secretKey)
  })
})
