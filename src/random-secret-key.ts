/* global crypto */

import HumanFormat from './human-format'

export default function randomSecretKey () {
  const view = new Uint8Array(16)

  crypto.getRandomValues(view)

  return HumanFormat.stringify(view.buffer)
}
