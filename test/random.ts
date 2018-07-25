import assert = require('assert')

import Core from '../src/core'

describe('Random', () => {
  it('gives a random master password', () => {
    const seen = new Set()

    for (let i = 0; i < 4096; i++) {
      const password = Core.randomMasterPassword()
      const parts = password.split(' ')
      const alpha = parts.filter(part => /^[a-z]+$/.test(part))
      const numeric = parts.filter(part => /^[0-9]+$/.test(part))

      assert.strictEqual(parts.length, 5)
      assert.strictEqual(alpha.length, 4)
      assert.strictEqual(numeric.length, 1)
      assert.strictEqual(seen.has(password), false)

      seen.add(password)
    }
  })

  it('gives random account password', () => {
    const seen = new Set()

    for (let i = 0; i < 4096; i++) {
      const password = Core.randomAccountPassword()

      assert.strictEqual(/[a-z]/.test(password), true)
      assert.strictEqual(/[A-Z]/.test(password), true)
      assert.strictEqual(/[0-9]/.test(password), true)
      assert.strictEqual(/([0-9a-zA-Z]{3}-){3}[0-9a-zA-Z]{3}/.test(password), true)
      assert.strictEqual(seen.has(password), false)

      seen.add(password)
    }
  })
})
