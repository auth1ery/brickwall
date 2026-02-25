const express = require('express')
const cookieParser = require('cookie-parser')
const rateLimit = require('express-rate-limit')
const jwt = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid')
const path = require('path')
const crypto = require('crypto')

const app = express()
const PORT = process.env.PORT || 3000
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex')
const PASS_SECRET = process.env.PASS_SECRET || crypto.randomBytes(48).toString('hex')
const TOKEN_TTL = 60 * 60 * 24

const KNOWN_CRAWLERS = [
  'googlebot','bingbot','slurp','duckduckbot','baiduspider',
  'yandexbot','sogou','exabot','facebot','ia_archiver',
  'msnbot','ahrefsbot','semrushbot','dotbot','petalbot'
]

const TOR_EXIT_PREFIXES = ['185.220.','199.87.154.','162.247.72.','171.25.193.']
const VPN_ASNS = ['AS9009','AS20473','AS14061','AS16276','AS24940']

const users = new Map()
const sites = new Map()
const requests = new Map()
const challenges = new Map()
const rateBuckets = new Map()
const apiKeys = new Map()


app.use(express.json())
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false })
const challengeLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false })
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false })

function requireAuth(req, res, next) {
  const token = req.cookies.bw_session
  if (!token) return res.status(401).json({ error: 'not authenticated' })
  try {
    req.user = jwt.verify(token, SECRET)
    next()
  } catch {
    res.clearCookie('bw_session')
    res.status(401).json({ error: 'session expired' })
  }
}

function isCrawler(ua) {
  if (!ua) return false
  const u = ua.toLowerCase()
  return KNOWN_CRAWLERS.some(c => u.includes(c))
}

function looksLikeTor(ip) {
  return TOR_EXIT_PREFIXES.some(p => (ip || '').startsWith(p))
}

function ipToFlag(ip) {
  if (!ip) return null
  if (looksLikeTor(ip)) return 'tor'
  return null
}

app.post('/api/auth/register', authLimiter, (req, res) => {
  const { email, password, name } = req.body
  if (!email || !password || !name) return res.status(400).json({ error: 'missing fields' })
  if (password.length < 8) return res.status(400).json({ error: 'password too short' })
  const existing = [...users.values()].find(u => u.email === email.toLowerCase())
  if (existing) return res.status(409).json({ error: 'email already registered' })
  const id = uuidv4()
  const hash = crypto.createHmac('sha256', PASS_SECRET).update(password).digest('hex')
  users.set(id, { id, email: email.toLowerCase(), name, hash, createdAt: Date.now() })
  const token = jwt.sign({ id, email: email.toLowerCase(), name }, SECRET, { expiresIn: '7d' })
  res.cookie('bw_session', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 })
  res.json({ ok: true, name })
})

app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'missing fields' })
  const user = [...users.values()].find(u => u.email === email.toLowerCase())
  if (!user) return res.status(401).json({ error: 'invalid credentials' })
  const hash = crypto.createHmac('sha256', PASS_SECRET).update(password).digest('hex')
  if (hash !== user.hash) return res.status(401).json({ error: 'invalid credentials' })
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, SECRET, { expiresIn: '7d' })
  res.cookie('bw_session', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 })
  res.json({ ok: true, name: user.name })
})

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('bw_session')
  res.json({ ok: true })
})

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name })
})

app.delete("/api/auth/account", requireAuth, (req, res) => {
  const userId = req.user.id
  const userSites = [...sites.values()].filter(s => s.userId === userId)
  for (const s of userSites) {
    apiKeys.delete(s.key)
    requests.delete(s.id)
    sites.delete(s.id)
  }
  users.delete(userId)
  res.clearCookie("bw_session")
  res.json({ ok: true })
})

app.get('/api/sites', requireAuth, (req, res) => {
  const userSites = [...sites.values()].filter(s => s.userId === req.user.id)
  res.json(userSites)
})

app.post('/api/sites', requireAuth, (req, res) => {
  const { name, domain } = req.body
  if (!name || !domain) return res.status(400).json({ error: 'missing fields' })
  const id = uuidv4()
  const key = 'bw_live_' + crypto.randomBytes(16).toString('hex')
  const site = {
    id, userId: req.user.id, name, domain: domain.replace(/^https?:\/\//, '').split('/')[0],
    key, createdAt: Date.now(), active: true,
    settings: { allowCrawlers: true, blockTor: false, blockVpn: false, challengeTtl: 24 }
  }
  sites.set(id, site)
  apiKeys.set(key, id)
  requests.set(id, [])
  res.json(site)
})

app.put('/api/sites/:id', requireAuth, (req, res) => {
  const site = sites.get(req.params.id)
  if (!site || site.userId !== req.user.id) return res.status(404).json({ error: 'not found' })
  const allowed = ['name','settings']
  for (const k of allowed) {
    if (req.body[k] !== undefined) site[k] = req.body[k]
  }
  sites.set(site.id, site)
  res.json(site)
})

app.delete('/api/sites/:id', requireAuth, (req, res) => {
  const site = sites.get(req.params.id)
  if (!site || site.userId !== req.user.id) return res.status(404).json({ error: 'not found' })
  sites.delete(site.id)
  apiKeys.delete(site.key)
  requests.delete(site.id)
  res.json({ ok: true })
})

app.post('/api/sites/:id/rotate', requireAuth, (req, res) => {
  const site = sites.get(req.params.id)
  if (!site || site.userId !== req.user.id) return res.status(404).json({ error: 'not found' })
  apiKeys.delete(site.key)
  site.key = 'bw_live_' + crypto.randomBytes(16).toString('hex')
  apiKeys.set(site.key, site.id)
  sites.set(site.id, site)
  res.json({ key: site.key })
})

app.get('/api/sites/:id/requests', requireAuth, (req, res) => {
  const site = sites.get(req.params.id)
  if (!site || site.userId !== req.user.id) return res.status(404).json({ error: 'not found' })
  const reqs = requests.get(req.params.id) || []
  res.json(reqs)
})

app.get('/api/sites/:id/stats', requireAuth, (req, res) => {
  const site = sites.get(req.params.id)
  if (!site || site.userId !== req.user.id) return res.status(404).json({ error: 'not found' })
  const reqs = requests.get(req.params.id) || []
  const total = reqs.length
  const passed = reqs.filter(r => r.status === 'passed').length
  const blocked = reqs.filter(r => r.status === 'blocked').length
  const flagged = reqs.filter(r => r.status === 'flagged').length
  res.json({ total, passed, blocked, flagged })
})

app.post('/api/challenge/init', challengeLimiter, (req, res) => {
  const { siteKey, returnUrl } = req.body
  const ua = req.headers['user-agent'] || ''
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || ''

  if (!siteKey) return res.status(400).json({ error: 'missing site key' })
  const siteId = apiKeys.get(siteKey)
  if (!siteId) return res.status(404).json({ error: 'unknown site key' })
  const site = sites.get(siteId)
  if (!site || !site.active) return res.status(403).json({ error: 'site inactive' })

  const crawlerDetected = isCrawler(ua)
  const torDetected = looksLikeTor(ip)

  if (crawlerDetected && site.settings.allowCrawlers) {
    const token = jwt.sign({ siteId, type: 'pass', crawler: true }, SECRET, { expiresIn: TOKEN_TTL })
    const siteReqs = requests.get(siteId) || []
    siteReqs.unshift({ id: uuidv4(), siteId, country: 'Unknown', detected: 'crawler', status: 'passed', ts: Date.now(), ua })
    if (siteReqs.length > 500) siteReqs.length = 500
    requests.set(siteId, siteReqs)
    return res.json({ token, skip: true })
  }

  if (torDetected && site.settings.blockTor) {
    const siteReqs = requests.get(siteId) || []
    siteReqs.unshift({ id: uuidv4(), siteId, country: 'Unknown', detected: 'tor', status: 'blocked', ts: Date.now(), ua })
    if (siteReqs.length > 500) siteReqs.length = 500
    requests.set(siteId, siteReqs)
    return res.status(403).json({ error: 'blocked', reason: 'tor' })
  }

  const bucket = rateBuckets.get(ip) || { count: 0, reset: Date.now() + 60000 }
  if (Date.now() > bucket.reset) { bucket.count = 0; bucket.reset = Date.now() + 60000 }
  bucket.count++
  rateBuckets.set(ip, bucket)
  if (bucket.count > 15) {
    return res.status(429).json({ error: 'rate limited', retryAfter: Math.ceil((bucket.reset - Date.now()) / 1000) })
  }

  const challengeId = uuidv4()
  const target = Math.floor(Math.random() * 900000) + 100000
  const difficulty = torDetected ? 6 : 4
  challenges.set(challengeId, {
    siteId, siteKey, returnUrl, target, difficulty,
    ip, ua, expires: Date.now() + 120000,
    torDetected, crawlerDetected
  })

  setTimeout(() => challenges.delete(challengeId), 120000)

  res.json({ challengeId, target, difficulty, siteId })
})

app.post('/api/challenge/verify', challengeLimiter, (req, res) => {
  const { challengeId, nonce, elapsed } = req.body
  const ch = challenges.get(challengeId)
  if (!ch || Date.now() > ch.expires) return res.status(410).json({ error: 'challenge expired' })
  challenges.delete(challengeId)

  const site = sites.get(ch.siteId)
  if (!site) return res.status(404).json({ error: 'site not found' })

  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || ''

  const hash = crypto.createHash('sha256').update(challengeId + nonce).digest('hex')
  const prefix = '0'.repeat(ch.difficulty)
  const valid = hash.startsWith(prefix)

  const tooFast = elapsed < 200
  const suspicious = tooFast || !valid

  const detected = ch.torDetected ? 'tor' : ch.crawlerDetected ? 'crawler' : 'N/A'
  const status = suspicious ? 'blocked' : 'passed'

  const siteReqs = requests.get(ch.siteId) || []
  siteReqs.unshift({
    id: uuidv4(), siteId: ch.siteId,
    country: 'United States',
    detected,
    status,
    ts: Date.now(),
    ua: ch.ua
  })
  if (siteReqs.length > 500) siteReqs.length = 500
  requests.set(ch.siteId, siteReqs)

  if (suspicious) return res.status(403).json({ error: 'challenge failed' })

  const ttl = (site.settings.challengeTtl || 24) * 3600
  const token = jwt.sign({ siteId: ch.siteId, type: 'pass' }, SECRET, { expiresIn: ttl })
  res.json({ token })
})

app.post('/api/challenge/check', apiLimiter, (req, res) => {
  const { token, siteKey } = req.body
  if (!token || !siteKey) return res.status(400).json({ valid: false })
  const siteId = apiKeys.get(siteKey)
  if (!siteId) return res.status(400).json({ valid: false })
  try {
    const payload = jwt.verify(token, SECRET)
    if (payload.siteId !== siteId) return res.json({ valid: false })
    res.json({ valid: true })
  } catch {
    res.json({ valid: false })
  }
})

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'))
})

app.listen(PORT, () => {
  console.log(`brickwall running on :${PORT}`)
})
