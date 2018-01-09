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

describe('Sync', () => {
  let core: Core
  let stateA: State
  let stateB: State

  const handle = Core.randomHandle()
  const secretKey = Core.randomSecretKey()
  const masterPassword = Core.randomMasterPassword()

  before(() => {
    core = Object.assign(new Core(), {
      apiClient: new MockApiClient(),
      storage: new MockStorage(),
    })

    stateA = core.init()
  })

  before('signup', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (stateA.kind !== 'empty') throw new Error('Expected an empty state')

    stateA = await core.signup(stateA, handle, secretKey, masterPassword, false)
  })

  before('create first account', async function () {
    if (stateA.kind !== 'connected') throw new Error('Expected a connected state')

    assert.strictEqual(stateA.decryptedEntries.length, 0)

    stateA = await core.createAccount(stateA, acc1Id, acc1Data)

    assert.strictEqual(stateA.decryptedEntries.length, 1)
    assert.deepStrictEqual(core.getParsedEntries(stateA), { accounts: { [acc1Id]: acc1Data }, inbox: {} })
  })

  after('clear stored data', async function () {
    await core.clearStoredData(stateB)
  })

  it('syncs changelog entries between clients', async function () {
    if (stateA.kind !== 'connected') throw new Error('Expected a connected state')

    const syncToken = core.getSyncToken(stateA)

    // Initialise second client
    stateB = core.init(syncToken)
    if (stateB.kind !== 'locked') throw new Error('Expected a locked state')

    // Unlock second client
    stateB = await core.unlock(stateB, masterPassword)
    if (stateB.kind !== 'connected') throw new Error('Expected a connected state')

    // Perform sync
    stateB = await core.sync(stateB)

    assert.strictEqual(stateB.decryptedEntries.length, 1)
    assert.deepStrictEqual(core.getParsedEntries(stateB), { accounts: { [acc1Id]: acc1Data }, inbox: {} })

    stateA = await core.createAccount(stateA, acc2Id, acc2Data)
    stateB = await core.createAccount(stateB, acc3Id, acc3Data)

    // Perform sync
    stateA = await core.sync(stateA)
    stateB = await core.sync(stateB)

    assert.strictEqual(stateA.decryptedEntries.length, 3)
    assert.deepStrictEqual(core.getParsedEntries(stateA), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data, [acc3Id]: acc3Data }, inbox: {} })

    assert.strictEqual(stateB.decryptedEntries.length, 3)
    assert.deepStrictEqual(core.getParsedEntries(stateB), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data, [acc3Id]: acc3Data }, inbox: {} })
  })

  it('throws when sync would override stored credentials', async function () {
    assert.throws(
      () => core.init('05DK3C95SQM2TZAD8AP0NXPB5CT5GZSPC8438YSYBGRD0CBRF8BC'),
      (err) => err.code === 'CONFLICTING_CREDENTIALS'
    )
  })
})
