declare class TextDecoder {
  constructor (encoding: string)
  decode: (buffer: ArrayBuffer) => string
}

declare class TextEncoder {
  constructor (encoding: string)
  encode: (text: string) => ArrayBuffer
}

interface Window {
  TextDecoder: typeof TextDecoder
  TextEncoder: typeof TextEncoder
}
