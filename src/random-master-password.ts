/* global crypto */

import wordList = require('./wordlist')

export default function randomMasterPassword () {
  if (wordList.length !== 8192) {
    throw new Error('Expected word list to contain 8192 entries')
  }

  const data = new Uint32Array(6)

  crypto.getRandomValues(data)

  const word1 = wordList[Math.trunc((data[0] / 4294967296) * wordList.length)]
  const word2 = wordList[Math.trunc((data[1] / 4294967296) * wordList.length)]
  const word3 = wordList[Math.trunc((data[2] / 4294967296) * wordList.length)]
  const word4 = wordList[Math.trunc((data[3] / 4294967296) * wordList.length)]
  const digit = String(Math.trunc((data[4] / 4294967296) * 10))
  const position = Math.trunc((data[5] / 4294967296) * 5)

  switch (position) {
    case 0: return [digit, word1, word2, word3, word4].join(' ')
    case 1: return [word1, digit, word2, word3, word4].join(' ')
    case 2: return [word1, word2, digit, word3, word4].join(' ')
    case 3: return [word1, word2, word3, digit, word4].join(' ')
    case 4: return [word1, word2, word3, word4, digit].join(' ')
  }

  throw new Error('Unreachable code')
}
