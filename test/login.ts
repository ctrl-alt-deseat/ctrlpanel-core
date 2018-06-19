import _ = require('./_shims')

import assert = require('assert')
import assertRejects = require('assert-rejects')

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

    await core.signup(state, { handle, secretKey, masterPassword }, false)
  })

  it('performs a login against the api', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    const newState = await core.login(state, { handle, secretKey, masterPassword }, false)

    assert.ok(newState.authToken)
    assert.strictEqual(newState.decryptedEntries.length, 0)
    assert.strictEqual(newState.handle, handle)
    assert.strictEqual(newState.kind, 'connected')
    assert.strictEqual(newState.secretKey, secretKey)
  })

  it('reports when handle not found', async function () {
    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    await assertRejects(
      core.login(state, { handle: 'x', secretKey, masterPassword }, false),
      (err) => err.code === 'HANDLE_NOT_FOUND'
    )
  })

  it('reports when wrong secret key/master password', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    await assertRejects(
      core.login(state, { handle, secretKey, masterPassword: 'x' }, false),
      (err) => err.code === 'WRONG_SECRET_KEY_OR_MASTER_PASSWORD'
    )
  })
})
