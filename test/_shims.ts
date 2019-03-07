const store = new Map<string, any>()

const mockLocalStorage = {
  getItem (key: string) { return store.get(key) },
  removeItem (key: string) { return store.delete(key) },
  setItem (key: string, value: any) { store.set(key, value) },
}

Object.assign(global, {
  crypto: require('@trust/webcrypto'),
  localStorage: mockLocalStorage,
})
