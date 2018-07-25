import { FannyPack } from '@fanny-pack/core'

import { ChangelogEntryOutput } from './api-client'
import { EncryptedData } from './crypto'
import HumanFormat from './human-format'

export interface Credentials {
  handle: string
  secretKey: string
}

export interface FastTrack {
  dekSalt: string
  srpPrivateKey: EncryptedData
}

function stringifyCredentials (credentials: Credentials): string {
  return `${credentials.handle.replace(/-/g, '')}${credentials.secretKey.replace(/-/g, '')}`
}

function parseCredentials (input: string): Credentials {
  const handle = HumanFormat.dashify(input.slice(0, 26))
  const secretKey = HumanFormat.dashify(input.slice(26))

  return { handle, secretKey }
}

function changelogKey (changelogEntry: ChangelogEntryOutput) {
  return `changelog/${changelogEntry.createdAt}/${changelogEntry.id}`
}

const kFannyPack = Symbol('fanny-pack')
const kSyncCredentialsToLocalStorage = Symbol('sync-credentials-to-local-storage')

export default class LocalStorage {
  [kFannyPack]: FannyPack
  [kSyncCredentialsToLocalStorage]: boolean

  constructor (fannyPack: FannyPack, syncCredentialsToLocalStorage: boolean) {
    this[kFannyPack] = fannyPack
    this[kSyncCredentialsToLocalStorage] = syncCredentialsToLocalStorage
  }

  async clear (): Promise<void> {
    /* First remove cached changelog entries */
    const range = { gte: 'changelog/', lt: 'changelog0' }

    for await (const key of this[kFannyPack].keys(range)) {
      await this[kFannyPack].delete(key)
    }

    /* Then cached fast track data */
    await this[kFannyPack].delete('fast-track')

    /* Finally remove the login credentials */
    await this[kFannyPack].delete('credentials')

    if (this[kSyncCredentialsToLocalStorage]) {
      window.localStorage.removeItem('credentials')
    }
  }

  async putChangelogEntries (changelogEntries: ChangelogEntryOutput[]): Promise<void> {
    await Promise.all(changelogEntries.map((changelogEntry) => {
      return this[kFannyPack].set(changelogKey(changelogEntry), changelogEntry)
    }))
  }

  async getAllChangelogEntries (): Promise<ChangelogEntryOutput[]> {
    const result: ChangelogEntryOutput[] = []
    const range = { gte: 'changelog/', lt: 'changelog0' }

    for await (const entry of this[kFannyPack].values(range)) {
      result.push(entry as ChangelogEntryOutput)
    }

    return result
  }

  async readCredentials (): Promise<Credentials | null> {
    const firstSource = await this[kFannyPack].get('credentials') as Credentials | undefined
    if (firstSource) return firstSource

    if (this[kSyncCredentialsToLocalStorage]) {
      const secondSource = window.localStorage.getItem('credentials')
      if (secondSource) return parseCredentials(secondSource)
    }

    return null
  }

  async writeCredentials (data: Credentials): Promise<void> {
    await this[kFannyPack].set('credentials', data)

    if (this[kSyncCredentialsToLocalStorage]) {
      window.localStorage.setItem('credentials', stringifyCredentials(data))
    }
  }

  async readFastTrack (): Promise<FastTrack | null> {
    return (await this[kFannyPack].get('fast-track') as FastTrack | undefined) || null
  }

  async writeFastTrack (data: FastTrack): Promise<void> {
    await this[kFannyPack].set('fast-track', data)
  }
}
