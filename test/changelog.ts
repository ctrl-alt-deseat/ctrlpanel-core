import _ = require('./_shims')

import assert = require('assert')

import MockApiClient from './_api-client'
import MockStorage from './_storage'

import Core, { State } from '../src/core'

const acc1Id = '86ee6a06-7112-4bb6-bf41-fbf02ba32bc2'
const acc1Data = { hostname: 'example.com', handle: 'Test', password: 'och-dWB-ea3-PKR' }

const acc2Id = 'f2e7b12b-b6e6-4d6c-b732-4778b7c0685b'
const acc2Data = { hostname: 'google.com', handle: 'LinusU', password: 'LGp-HeA-hKm-ag7' }

const acc3Id = 'd68fb9fd-16b8-49c4-ba39-14fd66494f8d'
const acc3Data = { hostname: 'github.com', handle: 'linus@folkdatorn.se', password: 'HAP-6LJ-Qzo-WPF' }

const inbox1Id = '280ab0ae-195b-4eb1-974b-7ebeeb1cab1d'
const inbox1Data = { hostname: 'github.com', email: 'linus@folkdatorn.se' }

describe('Changelog', () => {
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

  it('derives a single state from changelog entries', async function () {
    if (state.kind !== 'connected') throw new Error('Expected a connected state')

    assert.strictEqual(state.decryptedEntries.length, 0)

    state = await core.createAccount(state, acc1Id, acc1Data)

    assert.strictEqual(state.decryptedEntries.length, 1)
    assert.deepStrictEqual(core.getParsedEntries(state), { accounts: { [acc1Id]: acc1Data }, inbox: {} })

    state = await core.createAccount(state, acc2Id, acc2Data)

    assert.strictEqual(state.decryptedEntries.length, 2)
    assert.deepStrictEqual(core.getParsedEntries(state), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data }, inbox: {} })

    state = await core.createInboxEntry(state, inbox1Id, inbox1Data)

    assert.strictEqual(state.decryptedEntries.length, 3)
    assert.deepStrictEqual(core.getParsedEntries(state), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data }, inbox: { [inbox1Id]: inbox1Data } })

    state = await core.deleteInboxEntry(state, inbox1Id)
    state = await core.createAccount(state, acc3Id, acc3Data)

    assert.strictEqual(state.decryptedEntries.length, 5)
    assert.deepStrictEqual(core.getParsedEntries(state), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data, [acc3Id]: acc3Data }, inbox: {} })
  })
})
