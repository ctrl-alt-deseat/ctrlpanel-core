import _ = require('./_shims')

import assert = require('assert')

import MockApiClient from './_api-client'
import MockStorage from './_storage'

import Core, { State } from '../src/core'

const acc1Id = '86ee6a06-7112-4bb6-bf41-fbf02ba32bc2'
const acc1Data = { hostname: 'example.com', handle: 'Test', password: 'och-dWB-ea3-PKR' }

const acc2Id = 'f2e7b12b-b6e6-4d6c-b732-4778b7c0685b'
const acc2Data = { hostname: 'google.com', handle: 'LinusU', password: 'LGp-HeA-hKm-ag7' }

describe('Import', () => {
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

    state = await core.signup(state, handle, secretKey, masterPassword, false)
  })

  it('imports accounts from deseat.me', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (state.kind !== 'connected') throw new Error('Expected a connected state')

    assert.strictEqual(state.decryptedEntries.length, 0)
    assert.deepStrictEqual(core.getParsedEntries(state), { accounts: {}, inbox: {} })

    state = await core.importFromDeseatme(state, 'x')

    const data = core.getParsedEntries(state)
    const keys = Object.keys(data.inbox)

    assert.strictEqual(state.decryptedEntries.length, 2)
    assert.strictEqual(keys.length, 2)

    const keyA = data.inbox[keys[0]].hostname === 'a.deseat.me' ? keys[0] : keys[1]
    const keyB = data.inbox[keys[0]].hostname === 'b.deseat.me' ? keys[0] : keys[1]

    assert.deepStrictEqual(data.inbox[keyA], { email: 'test@example.com', hostname: 'a.deseat.me' })
    assert.deepStrictEqual(data.inbox[keyB], { email: 'test@example.com', hostname: 'b.deseat.me' })
  })
})
