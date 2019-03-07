import assert = require('assert')
import assertRejects = require('assert-rejects')
import FannyPackMemory = require('@fanny-pack/memory')

import MockApiClient from './_api-client'

import Core, { State } from '../src/core'

describe('Legacy', () => {
  const apiClient = new MockApiClient()

  const handle = Core.randomHandle()
  const secretKey = Core.randomSecretKey()
  const masterPassword = Core.randomMasterPassword()

  afterEach(() => {
    localStorage.removeItem('credentials')
  })

  it('syncs credentials with localStorage', async function () {
    this.timeout(10000)
    this.slow(1300)

    const core = Object.assign(new Core({ storage: new FannyPackMemory(), syncCredentialsToLocalStorage: true }), { apiClient })
    let state: State = await core.init()

    assert.strictEqual(localStorage.getItem('credentials'), undefined)

    if (state.kind !== 'empty') throw new Error('Expected an empty state')
    state = await core.signup(state, { handle, secretKey, masterPassword })

    assert.strictEqual(localStorage.getItem('credentials'), `${handle}${secretKey}`.replace(/-/g, ''))

    if (state.kind !== 'connected') throw new Error('Expected a connected state')
    state = await core.clearStoredData(state)

    assert.strictEqual(localStorage.getItem('credentials'), undefined)
  })

  it('reads credentials from localStorage', async function () {
    this.timeout(10000)
    this.slow(1300)

    localStorage.setItem('credentials', `${handle}${secretKey}`.replace(/-/g, ''))

    const core = Object.assign(new Core({ storage: new FannyPackMemory(), syncCredentialsToLocalStorage: true }), { apiClient })
    let state: State = await core.init()

    if (state.kind !== 'locked') throw new Error('Expected a locked state')

    assert.strictEqual(state.handle, handle)
    assert.strictEqual(state.secretKey, secretKey)

    await assertRejects(core.unlock(state, { masterPassword: 'x' }), (err: any) => err.code === 'WRONG_MASTER_PASSWORD')

    state = await core.unlock(state, { masterPassword })

    if (state.kind !== 'connected') throw new Error('Expected a connected state')

    state = await core.deleteUser(state)

    if (state.kind !== 'empty') throw new Error('Expected a empty state')
  })
})
