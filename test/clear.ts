import assert = require('assert')
import FannyPackMemory = require('@fanny-pack/memory')
import { FannyPack } from '@fanny-pack/core'

import MockApiClient from './_api-client'

import Core, { State } from '../src/core'

const acc1Id = '86ee6a06-7112-4bb6-bf41-fbf02ba32bc2'
const acc1Data = { hostname: 'example.com', handle: 'Test', password: 'och-dWB-ea3-PKR' }

const acc2Id = 'f2e7b12b-b6e6-4d6c-b732-4778b7c0685b'
const acc2Data = { hostname: 'google.com', handle: 'LinusU', password: 'LGp-HeA-hKm-ag7' }

async function getAllKeys (fp: FannyPack) {
  const result: string[] = []
  for await (const key of fp.keys()) result.push(key)
  return result
}

describe('Clear', () => {
  const apiClient = new MockApiClient()

  const handle = Core.randomHandle()
  const secretKey = Core.randomSecretKey()
  const masterPassword = Core.randomMasterPassword()

  it('clears stored data', async function () {
    this.timeout(10000)
    this.slow(1300)

    const storage = new FannyPackMemory()

    await storage.set('do-not-delete', 'Hello, World!')

    const core = Object.assign(new Core({ storage }), { apiClient })
    let state: State = await core.init()

    if (state.kind !== 'empty') throw new Error('Expected an empty state')
    state = await core.signup(state, { handle, secretKey, masterPassword })
    state = await core.createAccount(state, acc1Id, acc1Data)
    state = await core.createAccount(state, acc2Id, acc2Data)

    assert.strictEqual((await getAllKeys(storage)).length, 5)

    state = await core.clearStoredData(state)

    assert.strictEqual((await getAllKeys(storage)).length, 1)
    assert.strictEqual(await storage.get('do-not-delete'), 'Hello, World!')
  })
})
