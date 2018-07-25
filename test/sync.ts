import assert = require('assert')
import assertRejects = require('assert-rejects')
import FannyPackMemory = require('@fanny-pack/memory')

import MockApiClient from './_api-client'

import Core, { State } from '../src/core'

const acc1Id = '86ee6a06-7112-4bb6-bf41-fbf02ba32bc2'
const acc1Data = { hostname: 'example.com', handle: 'Test', password: 'och-dWB-ea3-PKR' }

const acc2Id = 'f2e7b12b-b6e6-4d6c-b732-4778b7c0685b'
const acc2Data = { hostname: 'google.com', handle: 'LinusU', password: 'LGp-HeA-hKm-ag7' }

const acc3Id = 'd68fb9fd-16b8-49c4-ba39-14fd66494f8d'
const acc3Data = { hostname: 'github.com', handle: 'linus@folkdatorn.se', password: 'HAP-6LJ-Qzo-WPF' }
const acc3Update = { hostname: 'github.com', handle: 'linus@folkdatorn.se', password: 'tSv-N8f-KV8-PMh' }

describe('Sync', () => {
  let coreA: Core
  let coreB: Core
  let stateA: State
  let stateB: State

  const handle = Core.randomHandle()
  const secretKey = Core.randomSecretKey()
  const masterPassword = Core.randomMasterPassword()

  before(async () => {
    const apiClient = new MockApiClient()

    coreA = Object.assign(new Core({ storage: new FannyPackMemory() }), { apiClient })
    coreB = Object.assign(new Core({ storage: new FannyPackMemory() }), { apiClient })

    stateA = await coreA.init()
  })

  before('signup', async function () {
    this.timeout(10000)
    this.slow(1300)

    if (stateA.kind !== 'empty') throw new Error('Expected an empty state')

    stateA = await coreA.signup(stateA, { handle, secretKey, masterPassword })
  })

  before('create first account', async function () {
    if (stateA.kind !== 'connected') throw new Error('Expected a connected state')

    assert.strictEqual(stateA.decryptedEntries.length, 0)

    stateA = await coreA.createAccount(stateA, acc1Id, acc1Data)

    assert.strictEqual(stateA.decryptedEntries.length, 1)
    assert.deepStrictEqual(coreA.getParsedEntries(stateA), { accounts: { [acc1Id]: acc1Data }, inbox: {} })
  })

  it('syncs changelog entries between clients', async function () {
    if (stateA.kind !== 'connected') throw new Error('Expected a connected state')

    const syncToken = coreA.getSyncToken(stateA)

    // Initialise second client
    stateB = await coreB.init(syncToken)
    if (stateB.kind !== 'locked') throw new Error('Expected a locked state')

    // Unlock second client
    stateB = await coreB.unlock(stateB, { masterPassword })
    if (stateB.kind !== 'connected') throw new Error('Expected a connected state')

    // Perform sync
    stateB = await coreB.sync(stateB)

    assert.strictEqual(stateB.decryptedEntries.length, 1)
    assert.deepStrictEqual(coreB.getParsedEntries(stateB), { accounts: { [acc1Id]: acc1Data }, inbox: {} })

    stateA = await coreA.createAccount(stateA, acc2Id, acc2Data)
    stateB = await coreB.createAccount(stateB, acc3Id, acc3Data)
    stateB = await coreB.updateAccount(stateB, acc3Id, acc3Update)

    // Perform sync
    stateA = await coreA.sync(stateA)
    stateB = await coreB.sync(stateB)

    assert.strictEqual(stateA.decryptedEntries.length, 4)
    assert.deepStrictEqual(coreA.getParsedEntries(stateA), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data, [acc3Id]: acc3Update }, inbox: {} })

    assert.strictEqual(stateB.decryptedEntries.length, 4)
    assert.deepStrictEqual(coreB.getParsedEntries(stateB), { accounts: { [acc1Id]: acc1Data, [acc2Id]: acc2Data, [acc3Id]: acc3Update }, inbox: {} })
  })

  it('throws when sync would override stored credentials', async function () {
    assertRejects(
      coreA.init('05DK3C95SQM2TZAD8AP0NXPB5CT5GZSPC8438YSYBGRD0CBRF8BC'),
      (err) => err.code === 'CONFLICTING_CREDENTIALS'
    )
  })
})
