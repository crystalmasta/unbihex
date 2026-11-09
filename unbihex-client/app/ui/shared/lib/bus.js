// Named signals between slices that may not import each other: a lower layer emits,
// app/ connects the signal to the upper layer's function.
const handlers = new Map();

export function on(name, fn) {
  if (!handlers.has(name)) handlers.set(name, []);
  handlers.get(name).push(fn);
}

export function emit(name, ...args) {
  for (const fn of handlers.get(name) || []) fn(...args);
}
