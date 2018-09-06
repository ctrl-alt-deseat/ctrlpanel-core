const store = new Map<string, any>()

const mockLocalStorage = {
  getItem (key) { return store.get(key) },
  removeItem (key) { return store.delete(key) },
  setItem (key, value) { store.set(key, value) },
}

Object.assign(global, {
  crypto: require('@trust/webcrypto'),
  localStorage: mockLocalStorage,
})
