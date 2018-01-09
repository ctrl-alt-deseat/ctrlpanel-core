import { DB } from 'idb'

import { ChangelogEntryOutput } from '../src/api-client'
import LocalStorage, { Credentials, FastTrack } from '../src/local-storage'

class MockStorage implements LocalStorage {
  private credentials: Credentials | null = null
  private fastTrack: FastTrack | null = null
  private changelogEntries: ChangelogEntryOutput[] = []

  async clear () {
    this.credentials = null
    this.fastTrack = null
    this.changelogEntries = []
  }

  readCredentials () { return this.credentials }
  writeCredentials (credentials: Credentials) { this.credentials = credentials }

  readFastTrack () { return this.fastTrack }
  writeFastTrack (fastTrack: FastTrack) { this.fastTrack = fastTrack }

  async getAllChangelogEntries () { return this.changelogEntries }
  async putChangelogEntries (entries: ChangelogEntryOutput[]) { this.changelogEntries.push(...entries) }
}

export default MockStorage
