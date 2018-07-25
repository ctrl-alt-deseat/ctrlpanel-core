import assert = require('assert')
import assertRejects = require('assert-rejects')
import FannyPackMemory = require('@fanny-pack/memory')

import MockApiClient from './_api-client'

import Core, { State } from '../src/core'

describe('Login', () => {
  let core: Core
  let state: State

  const handle = Core.randomHandle()
  const secretKey = Core.randomSecretKey()
  const masterPassword = Core.randomMasterPassword()

  before(async () => {
    core = Object.assign(new Core({ storage: new FannyPackMemory() }), { apiClient: new MockApiClient() })
    state = await core.init()
  })

  before('signup', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    await core.signup(state, { handle, secretKey, masterPassword })
  })

  it('performs a login against the api', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    const newState = await core.login(state, { handle, secretKey, masterPassword })

    assert.ok(newState.authToken)
    assert.strictEqual(newState.decryptedEntries.length, 0)
    assert.strictEqual(newState.handle, handle)
    assert.strictEqual(newState.kind, 'connected')
    assert.strictEqual(newState.secretKey, secretKey)
  })

  it('reports when handle not found', async function () {
    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    await assertRejects(
      core.login(state, { handle: 'x', secretKey, masterPassword }),
      (err) => err.code === 'HANDLE_NOT_FOUND'
    )
  })

  it('reports when wrong secret key/master password', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')

    await assertRejects(
      core.login(state, { handle, secretKey, masterPassword: 'x' }),
      (err) => err.code === 'WRONG_SECRET_KEY_OR_MASTER_PASSWORD'
    )
  })
})
