import getRandomByte = require('get-random-byte')

const SYMBOLS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghkmnopqrstuvwxyz'.split('')
const PADDING = Array.from({ length: 36 }, () => '')
const TABLE = [...SYMBOLS, ...SYMBOLS, ...SYMBOLS, ...SYMBOLS, ...PADDING]

const reValidPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/

/**
 * @returns {string} A human readable password with just over 69 bits of entropy
 */
export default function randomAccountPassword (): string {
  let result = ''

  while (result.length < 12) {
    result += TABLE[getRandomByte()]
  }

  if (!reValidPassword.test(result)) {
    return randomAccountPassword()
  }

  return `${result.substring(0, 3)}-${result.substring(3, 6)}-${result.substring(6, 9)}-${result.substring(9, 12)}`
}
