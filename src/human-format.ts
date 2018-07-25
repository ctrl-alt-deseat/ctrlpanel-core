import arrayBufferToHex = require('array-buffer-to-hex')
import base32Decode = require('base32-decode')
import base32Encode = require('base32-encode')

function dashify (input: string) {
  /* istanbul ignore if */
  if (input.length !== 26) {
    throw new Error('Expected 26 chars of data')
  }

  const parts = [
    input.substring(0, 4),
    input.substring(4, 10),
    input.substring(10, 16),
    input.substring(16, 22),
    input.substring(22, 26)
  ]

  return parts.join('-')
}

function stringify (input: ArrayBuffer) {
  /* istanbul ignore if */
  if (input.byteLength !== 16) {
    throw new Error('Expected 16 bytes of data')
  }

  return dashify(base32Encode(input, 'Crockford'))
}

function parse (input: string) {
  return base32Decode(input.replace(/-/g, ''), 'Crockford')
}

function toHex (input: string) {
  return arrayBufferToHex(parse(input))
}

export default { dashify, stringify, parse, toHex }
