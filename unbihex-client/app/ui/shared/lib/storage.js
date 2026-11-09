// localStorage where the WebView allows it; without it the fallback.
export function loadString(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

export function saveString(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {}
}
