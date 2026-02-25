(function() {
  var script = document.currentScript || (function() {
    var scripts = document.getElementsByTagName('script')
    return scripts[scripts.length - 1]
  })()

  var siteKey = script.getAttribute('data-site')
  var apiBase = script.getAttribute('data-api') || 'https://brickwall.onrender.com'
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

  function getReturnUrl() {
    return encodeURIComponent(window.location.href)
  }

  function redirect() {
    var url = challengeBase + '/challenge.html?k=' + encodeURIComponent(siteKey) + '&r=' + getReturnUrl()
    window.location.replace(url)
  }

  function verifyWithServer(token, cb) {
    var xhr = new XMLHttpRequest()
    xhr.open('POST', apiBase + '/api/challenge/check', true)
    xhr.setRequestHeader('Content-Type', 'application/json')
    xhr.timeout = 5000
    xhr.onreadystatechange = function() {
      if (xhr.readyState !== 4) return
      try {
        var d = JSON.parse(xhr.responseText)
        cb(d.valid === true)
      } catch { cb(false) }
    }
    xhr.ontimeout = function() { cb(true) }
    xhr.onerror = function() { cb(true) }
    xhr.send(JSON.stringify({ token: token, siteKey: siteKey }))
  }

  function run() {
    var token = getToken()

    if (!token) { redirect(); return }

    if (!isTokenFresh(token)) {
      clearToken()
      redirect()
      return
    }

    verifyWithServer(token, function(valid) {
      if (!valid) {
        clearToken()
        redirect()
      }
    })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run)
  } else {
    run()
  }
})()
