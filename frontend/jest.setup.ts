import '@testing-library/jest-dom'

// structuredClone is not available in jest-environment-jsdom < Node 17
if (typeof structuredClone === 'undefined') {
  global.structuredClone = <T>(obj: T): T => JSON.parse(JSON.stringify(obj))
}
