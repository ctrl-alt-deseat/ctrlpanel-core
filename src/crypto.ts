import arrayBufferToHex = require('array-buffer-to-hex')
import hexToArrayBuffer = require('hex-to-array-buffer')
import ops = require('integer-array-ops')

import { Operation } from 'fast-json-patch'

import HumanFormat from './human-format'

const PBKDF2_HASH = 'SHA-512'
const PBKDF2_ITERATIONS = 500000

const HKDF_HASH = 'SHA-512'

const { TextDecoder, TextEncoder, crypto } = window

function stringToArrayBuffer (input: string): ArrayBuffer {
  const encoder = new TextEncoder('utf-8')
  return encoder.encode(input)
}

function arrayBufferToString (input: ArrayBuffer): string {
  const decoder = new TextDecoder('utf-8')
  return decoder.decode(input)
}

function generateAesGcmNonce () {
  // Q: Why 12 bytes?
  // A: https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
  const data = new Uint8Array(12)

  // Seed nonce
  crypto.getRandomValues(data)

  return data
}

async function PBKDF2 (input: ArrayBuffer, salt: ArrayBuffer) {
  const algo = { hash: PBKDF2_HASH, iterations: PBKDF2_ITERATIONS, name: 'PBKDF2', salt }
  const baseKey = await crypto.subtle.importKey('raw', input, { name: 'PBKDF2' }, false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey(algo, baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])

  return crypto.subtle.exportKey('raw', key)
}

async function HKDF (salt: ArrayBuffer, input: ArrayBuffer, info: ArrayBuffer) {
  const algo = { hash: HKDF_HASH, info, name: 'HKDF', salt }
  const baseKey = await crypto.subtle.importKey('raw', input, { name: 'HKDF' }, false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey(algo as any, baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])

  return crypto.subtle.exportKey('raw', key)
}

export interface KeyDerivationInput {
  password: string
  salt: ArrayBuffer
  handle: ArrayBuffer
  secretKey: ArrayBuffer
}

async function deriveCombinedKey ({ password, salt, handle, secretKey }: KeyDerivationInput) {
  const longPassword = PBKDF2(stringToArrayBuffer(password), salt)
  const longAccountKey = HKDF(handle, secretKey, stringToArrayBuffer('long-secret-key'))

  return ops.xor(new Uint8Array(await longPassword), new Uint8Array(await longAccountKey)).buffer
}

export type DataEncryptionKey = CryptoKey

async function deriveDataEncryptionKey (input: KeyDerivationInput): Promise<DataEncryptionKey> {
  return crypto.subtle.importKey('raw', await deriveCombinedKey(input), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

async function deriveSrpPrivateKey (input: KeyDerivationInput) {
  return arrayBufferToHex(await deriveCombinedKey(input))
}

export interface EncryptedData {
  ciphertext: string
  nonce: string
}

async function encrypt (dataEncryptionKey: DataEncryptionKey, data: ArrayBuffer): Promise<EncryptedData> {
  const nonce = generateAesGcmNonce()
  const algo = { name: 'AES-GCM', iv: nonce }

  const rawBytes = await crypto.subtle.encrypt(algo, dataEncryptionKey, data)

  return { ciphertext: arrayBufferToHex(rawBytes), nonce: arrayBufferToHex(nonce.buffer) }
}

async function decrypt (dataEncryptionKey: DataEncryptionKey, data: EncryptedData): Promise<ArrayBuffer> {
  const algo = { name: 'AES-GCM', iv: hexToArrayBuffer(data.nonce) }

  return crypto.subtle.decrypt(algo, dataEncryptionKey, hexToArrayBuffer(data.ciphertext))
}

export interface EncryptedEntry {
  nonce: string
  encryptedPatch: string
}

export interface DecryptedEntry extends EncryptedEntry {
  patch: Operation
}

async function decryptEntries (dataEncryptionKey: DataEncryptionKey, encryptedEntries: EncryptedEntry[]): Promise<DecryptedEntry[]> {
  return Promise.all(encryptedEntries.map(async (entry) => {
    const plaintext = await decrypt(dataEncryptionKey, { ciphertext: entry.encryptedPatch, nonce: entry.nonce })
    const patch = JSON.parse(arrayBufferToString(plaintext))

    return Object.assign({}, entry, { patch })
  }))
}

async function encryptPatch (patch: Operation, dataEncryptionKey: DataEncryptionKey): Promise<EncryptedEntry> {
  const enc = await encrypt(dataEncryptionKey, stringToArrayBuffer(JSON.stringify(patch)))

  return { encryptedPatch: enc.ciphertext, nonce: enc.nonce }
}

async function encryptSrpPrivateKey (dataEncryptionKey: DataEncryptionKey, srpPrivateKey: string) {
  return encrypt(dataEncryptionKey, stringToArrayBuffer(srpPrivateKey))
}

async function decryptSrpPrivateKey (dataEncryptionKey: DataEncryptionKey, encryptedData: EncryptedData) {
  return arrayBufferToString(await decrypt(dataEncryptionKey, encryptedData))
}

export default { deriveDataEncryptionKey, deriveSrpPrivateKey, decryptEntries, encryptPatch, encryptSrpPrivateKey, decryptSrpPrivateKey }
