// Shared Ladder proxy API client.
// Used by tools/ladder-engine and tools/qabio-playground.
// No dependencies. Expose as window.LadderAPI.

(function(){
  // Use the current origin for API calls, so the playground works on any
  // domain that has the proxy routed to /api/ladder/*. Local dev falls back
  // to the dev proxy on localhost:8801.
  const isLocal = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
  const SIGNET_API = isLocal ? 'http://localhost:8801' : location.origin;

  async function apiCallBase(endpoint, body) {
    const opts = body !== undefined
      ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
      : {};
    const r = await fetch(SIGNET_API + endpoint, opts);
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail?.rpc_error || data.detail || ('HTTP ' + r.status));
    return data;
  }

  // Build a wrapped apiCall bound to caller-supplied error/loading setters.
  // setLoading(endpoint|null), setError(string|null) — both optional.
  function makeApiCall({ setLoading, setError } = {}) {
    return async function apiCall(endpoint, body, silent) {
      if (!silent && setLoading) setLoading(endpoint);
      if (!silent && setError) setError(null);
      try {
        return await apiCallBase(endpoint, body);
      } catch (e) {
        if (!silent && setError) setError(e.message || String(e));
        return null;
      } finally {
        if (!silent && setLoading) setLoading(null);
      }
    };
  }

  window.LadderAPI = { SIGNET_API, apiCallBase, makeApiCall };
})();
