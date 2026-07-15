import '@testing-library/jest-dom'

// structuredClone is not available in jest-environment-jsdom < Node 17
if (typeof structuredClone === 'undefined') {
  global.structuredClone = <T>(obj: T): T => JSON.parse(JSON.stringify(obj))
}

// jsdom has no ResizeObserver — recharts' ResponsiveContainer needs one to mount.
if (typeof global.ResizeObserver === 'undefined') {
  global.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}
