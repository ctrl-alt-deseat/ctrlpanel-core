import base32Decode = require('base32-decode')
import base32Encode = require('base32-encode')
import idb, { DB } from 'idb'

import { ChangelogEntryOutput } from './api-client'
import { EncryptedData } from './crypto'
import HumanFormat from './human-format'

const DB_NAME = 'vault'
let DB_HANDLE: Promise<DB>

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

function getHandle () {
  if (!DB_HANDLE) {
    DB_HANDLE = idb.open(DB_NAME, 1, (db) => {
      const store = db.createObjectStore('changelogEntry', { autoIncrement: false, keyPath: 'id' })

      store.createIndex('createdAt', 'createdAt')
    })
  }

  return DB_HANDLE
}

export default class LocalStorage {
  async clear () {
    window.localStorage.removeItem('credentials')
    window.localStorage.removeItem('fast-track')

    const db = await getHandle()
    const tx = db.transaction('changelogEntry', 'readwrite')
    const store = tx.objectStore('changelogEntry')

    await store.clear()

    await tx.complete
  }

  async putChangelogEntries (changelogEntries: ChangelogEntryOutput[]) {
    const db = await getHandle()
    const tx = db.transaction('changelogEntry', 'readwrite')
    const store = tx.objectStore('changelogEntry')

    await Promise.all(changelogEntries.map(entry => store.put(entry)))

    await tx.complete
  }

  async getAllChangelogEntries () {
    const db = await getHandle()
    const tx = db.transaction('changelogEntry', 'readonly')
    const store = tx.objectStore('changelogEntry')
    const index = store.index('createdAt')

    const encryptedEntries = await index.getAll()

    await tx.complete

    return encryptedEntries as ChangelogEntryOutput[]
  }

  readCredentials (): Credentials | null {
    const input = window.localStorage.getItem('credentials')

    return (input ? parseCredentials(input) : null)
  }

  writeCredentials (credentials: Credentials) {
    window.localStorage.setItem('credentials', stringifyCredentials(credentials))
  }

  readFastTrack (): FastTrack | null {
    const input = window.localStorage.getItem('fast-track')

    return (input ? JSON.parse(input) : null)
  }

  writeFastTrack (data: FastTrack) {
    window.localStorage.setItem('fast-track', JSON.stringify(data))
  }
}
