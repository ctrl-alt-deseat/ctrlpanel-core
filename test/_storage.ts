import { DB } from 'idb'

import LocalStorage from '../src/local-storage'

class MockStorage implements LocalStorage {
  clear () { return undefined }

  readCredentials () { return undefined }
  readFastTrack () { return undefined }
  writeCredentials () { throw new Error('Unexpected call to writeCredentials') }
  writeFastTrack () { throw new Error('Unexpected call to writeFastTrack') }

  async getAllChangelogEntries () { return [] }
  async putChangelogEntries () { throw new Error('Unexpected call to putChangelogEntries') }
}

export default MockStorage
