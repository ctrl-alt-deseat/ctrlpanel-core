class TextEncoder {
  encode (input: string) {
    const src = Buffer.from(input)
    const view = new Uint8Array(src.byteLength)

    view.set(src, 0)

    return view.buffer
  }
}

class TextDecoder {
  decode (input: ArrayBuffer) {
    return Buffer.from(input).toString()
  }
}

Object.assign(global, {
  crypto: require('@trust/webcrypto'),
  TextEncoder: TextEncoder,
  TextDecoder: TextDecoder,

  window: {
    crypto: require('@trust/webcrypto'),
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder,
  }
})

export = {}
