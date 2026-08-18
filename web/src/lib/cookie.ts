import Cookies from 'js-cookie';

// The JWT itself now lives in an HttpOnly cookie set by the server and is NOT
// readable from JavaScript, so it cannot be stolen via XSS. This non-secret
// flag cookie only signals that a session exists so the UI can gate routing.
const AUTH_FLAG_KEY = 'nano-kvm-auth';

export function existToken() {
  return !!Cookies.get(AUTH_FLAG_KEY);
}

export function removeToken() {
  // Clear the client-visible flag. The HttpOnly token cookie is cleared by the
  // server on logout; any stale token is rejected on the next request anyway.
  Cookies.remove(AUTH_FLAG_KEY);
}
