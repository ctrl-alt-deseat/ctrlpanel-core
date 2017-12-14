/* global crypto */

import HumanFormat from './human-format'

export default function randomHandle () {
  const view = new Uint8Array(16)

  crypto.getRandomValues(view)

  // Embed version of account
  view[0] = 0x01

  return HumanFormat.stringify(view.buffer)
}
