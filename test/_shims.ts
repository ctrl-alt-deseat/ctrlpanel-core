Object.assign(global, {
  crypto: require('@trust/webcrypto'),

  window: {
    crypto: require('@trust/webcrypto')
  }
})

export = {}
