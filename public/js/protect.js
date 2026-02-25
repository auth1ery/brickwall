(function() {
  var script = document.currentScript || (function() {
    var scripts = document.getElementsByTagName('script')
    return scripts[scripts.length - 1]
  })()

  var siteKey = script.getAttribute('data-site')
  var challengeBase = script.getAttribute('data-challenge') || 'https://brickwall.onrender.com'

  if (!siteKey) return

  var storageKey = 'bw_token_' + siteKey
  var TOKEN_MARGIN = 60

  function getToken() {
    try { return localStorage.getItem(storageKey) } catch { return null }
  }

  function clearToken() {
    try { localStorage.removeItem(storageKey) } catch {}
  }

  function decodeJwtExp(token) {
    try {
      var parts = token.split('.')
      if (parts.length !== 3) return null
      var payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))
      return payload.exp || null
    } catch { return null }
  }

  function isTokenFresh(token) {
    var exp = decodeJwtExp(token)
    if (!exp) return false
    return (exp - TOKEN_MARGIN) > (Date.now() / 1000)
  }

  function saveTokenFromUrl() {
    try {
      var u = new URL(window.location.href)
      var t = u.searchParams.get('bw_token')
      if (!t) return
      u.searchParams.delete('bw_token')
      try { localStorage.setItem(storageKey, t) } catch {}
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, '', u.toString())
      }
    } catch {}
  }

  function redirect() {
    var current = window.location.href
    var u = new URL(current)
    u.searchParams.delete('bw_token')
    var returnUrl = u.toString()
    var dest = challengeBase + '/challenge.html?k=' + encodeURIComponent(siteKey) + '&r=' + encodeURIComponent(returnUrl)
    window.location.replace(dest)
  }

  function run() {
    saveTokenFromUrl()

    var token = getToken()

    if (!token) { redirect(); return }

    if (!isTokenFresh(token)) {
      clearToken()
      redirect()
      return
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run)
  } else {
    run()
  }
})()
