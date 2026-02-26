const express = require('express')
const cookieParser = require('cookie-parser')
const rateLimit = require('express-rate-limit')
const jwt = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid')
const path = require('path')
const crypto = require('crypto')
const { Pool } = require('pg')
let geoip = null
try { geoip = require('geoip-lite') } catch { console.warn('geoip-lite not installed — country lookup disabled. run: npm install geoip-lite') }

const app = express()
const PORT = process.env.PORT || 3000
const SECRET = process.env.JWT_SECRET || (() => { console.warn('WARNING: JWT_SECRET not set'); return crypto.randomBytes(48).toString('hex') })()
const PASS_SECRET = process.env.PASS_SECRET || (() => { console.warn('WARNING: PASS_SECRET not set'); return crypto.randomBytes(48).toString('hex') })()
const ADMIN_KEY = process.env.ADMIN_KEY || 'changeme'
const TOKEN_TTL = 60 * 60 * 24

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
})

const KNOWN_CRAWLERS = [
  'googlebot','bingbot','slurp','duckduckbot','baiduspider',
  'yandexbot','sogou','exabot','facebot','ia_archiver',
  'msnbot','ahrefsbot','semrushbot','dotbot','petalbot',
  'rogerbot','mj12bot','blexbot','majestic','neevabot',
  'applebot','twitterbot','linkedinbot','facebookexternalhit',
  'discordbot','slackbot','telegrambot','whatsapp',
  'pinterestbot','redditbot','ia_archiver','archive.org_bot'
]

const HEADLESS_SIGNALS = [
  'headlesschrome','headless chrome','phantomjs','nightmare','puppeteer',
  'playwright','selenium','webdriver','slimerjs','htmlunit','watir',
  'mechanize','python-requests','python-urllib','go-http-client',
  'java/','libwww','lwp-trivial','curl/','wget/','okhttp',
  'axios/','node-fetch','got/','superagent','aiohttp','httpx',
  'scrapy','nutch','larbin','jakarta','zgrab'
]

const DATACENTER_ORGS = [
  'amazon','aws','google cloud','googlecloud','microsoft azure','azure',
  'digitalocean','linode','vultr','hetzner','ovh','cloudflare',
  'fastly','akamai','leaseweb','psychz','tzulo','choopa','vultr',
  'serverius','m247','combahton','datacamp','quadranet','frantech',
  'sharktech','b2 net','coresite','zayo','cogent','hurricane electric',
  'serverpoint','multacom','limenet','serveraxis','servercentral',
  'layerhost','netcup','contabo','ionos','strato','plusserver'
]

const TOR_EXIT_PREFIXES = ['185.220.','199.87.154.','162.247.72.','171.25.193.']

function lookupCountry(ip) {
  if (!geoip || !ip) return 'Unknown'
  try {
    const cleaned = ip.replace(/^::ffff:/, '')
    const geo = geoip.lookup(cleaned)
    if (!geo || !geo.country) return 'Unknown'
    const names = {
      AF:'Afghanistan',AL:'Albania',DZ:'Algeria',AR:'Argentina',AU:'Australia',
      AT:'Austria',BE:'Belgium',BR:'Brazil',CA:'Canada',CL:'Chile',
      CN:'China',CO:'Colombia',HR:'Croatia',CZ:'Czech Republic',DK:'Denmark',
      EG:'Egypt',FI:'Finland',FR:'France',DE:'Germany',GH:'Ghana',
      GR:'Greece',HK:'Hong Kong',HU:'Hungary',IN:'India',ID:'Indonesia',
      IR:'Iran',IQ:'Iraq',IE:'Ireland',IL:'Israel',IT:'Italy',
      JP:'Japan',JO:'Jordan',KZ:'Kazakhstan',KE:'Kenya',KR:'South Korea',
      KW:'Kuwait',LB:'Lebanon',MY:'Malaysia',MX:'Mexico',MA:'Morocco',
      NL:'Netherlands',NZ:'New Zealand',NG:'Nigeria',NO:'Norway',PK:'Pakistan',
      PE:'Peru',PH:'Philippines',PL:'Poland',PT:'Portugal',QA:'Qatar',
      RO:'Romania',RU:'Russia',SA:'Saudi Arabia',RS:'Serbia',SG:'Singapore',
      ZA:'South Africa',ES:'Spain',SE:'Sweden',CH:'Switzerland',TW:'Taiwan',
      TH:'Thailand',TN:'Tunisia',TR:'Turkey',UA:'Ukraine',AE:'United Arab Emirates',
      GB:'United Kingdom',US:'United States',UY:'Uruguay',VN:'Vietnam',
      VE:'Venezuela',YE:'Yemen',ZW:'Zimbabwe'
    }
    return names[geo.country] || geo.country
  } catch { return 'Unknown' }
}

function detectUaType(ua) {
  if (!ua) return 'no-ua'
  const lower = ua.toLowerCase()
  for (const sig of HEADLESS_SIGNALS) {
    if (lower.includes(sig)) return 'headless'
  }
  return null
}

function detectDatacenter(ip) {
  if (!geoip || !ip) return false
  try {
    const cleaned = ip.replace(/^::ffff:/, '')
    const geo = geoip.lookup(cleaned)
    if (!geo || !geo.org) return false
    const org = geo.org.toLowerCase()
    return DATACENTER_ORGS.some(d => org.includes(d))
  } catch { return false }
}

const challenges = new Map()
const rateBuckets = new Map()

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      hash TEXT NOT NULL,
      created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
    )
  `)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      domain TEXT NOT NULL,
      key TEXT UNIQUE NOT NULL,
      created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      settings JSONB NOT NULL DEFAULT '{}'
    )
  `)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY,
      site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
      country TEXT NOT NULL DEFAULT 'Unknown',
      detected TEXT NOT NULL DEFAULT 'N/A',
      status TEXT NOT NULL,
      ts BIGINT NOT NULL,
      ua TEXT
    )
  `)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_requests_site_id ON requests(site_id)`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sites_user_id ON sites(user_id)`)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sites_key ON sites(key)`)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blog_posts (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      content TEXT NOT NULL,
      excerpt TEXT NOT NULL DEFAULT '',
      published_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
    )
  `)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_blog_slug ON blog_posts(slug)`)
  console.log('db ready')
}

function dbSiteToObj(row) {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    domain: row.domain,
    key: row.key,
    createdAt: Number(row.created_at),
    active: row.active,
    settings: row.settings || {}
  }
}

function dbReqToObj(row) {
  return {
    id: row.id,
    siteId: row.site_id,
    country: row.country,
    detected: row.detected,
    status: row.status,
    ts: Number(row.ts),
    ua: row.ua
  }
}

app.use(express.json({ limit: '64kb' }))
app.use(cookieParser())
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})
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

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' })
  next()
}

function isCrawler(ua) {
  if (!ua) return false
  const lower = ua.toLowerCase()
  return KNOWN_CRAWLERS.some(c => lower.includes(c))
}

function looksLikeTor(ip) {
  return TOR_EXIT_PREFIXES.some(p => (ip || '').startsWith(p))
}

function sanitizeChallengeUi(ui) {
  if (!ui || typeof ui !== 'object') return {}
  const out = {}
  if (ui.colors && typeof ui.colors === 'object') {
    const allowed = ['bg','accent','text','surface','muted','border','border2','text2']
    out.colors = {}
    for (const k of allowed) {
      if (typeof ui.colors[k] === 'string' && /^#[0-9a-fA-F]{3,6}$/.test(ui.colors[k].trim())) {
        out.colors[k] = ui.colors[k].trim()
      }
    }
  }
  if (typeof ui.css === 'string') out.css = ui.css.slice(0, 8192)
  if (typeof ui.headline === 'string') out.headline = ui.headline.slice(0, 120)
  if (typeof ui.subline === 'string') out.subline = ui.subline.slice(0, 300)
  if (typeof ui.logoText === 'string') out.logoText = ui.logoText.slice(0, 60)
  if (typeof ui.hideBadge === 'boolean') out.hideBadge = ui.hideBadge
  if (typeof ui.hideStepsLog === 'boolean') out.hideStepsLog = ui.hideStepsLog
  return out
}

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body
    if (!email || !password || !name) return res.status(400).json({ error: 'missing fields' })
    if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' })
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()])
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email already registered' })
    const id = uuidv4()
    const hash = crypto.createHmac('sha256', PASS_SECRET).update(password).digest('hex')
    await pool.query(
      'INSERT INTO users (id, email, name, hash) VALUES ($1, $2, $3, $4)',
      [id, email.toLowerCase(), name, hash]
    )
    const token = jwt.sign({ id, email: email.toLowerCase(), name }, SECRET, { expiresIn: '7d' })
    res.cookie('bw_session', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 })
    res.json({ ok: true, name })
  } catch (e) {
    console.error('register error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({ error: 'missing fields' })
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()])
    if (result.rows.length === 0) return res.status(401).json({ error: 'invalid credentials' })
    const user = result.rows[0]
    const hash = crypto.createHmac('sha256', PASS_SECRET).update(password).digest('hex')
    if (hash !== user.hash) return res.status(401).json({ error: 'invalid credentials' })
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, SECRET, { expiresIn: '7d' })
    res.cookie('bw_session', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 })
    res.json({ ok: true, name: user.name })
  } catch (e) {
    console.error('login error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('bw_session')
  res.json({ ok: true })
})

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name })
})

app.delete('/api/auth/account', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id])
    res.clearCookie('bw_session')
    res.json({ ok: true })
  } catch (e) {
    console.error('delete account error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.get('/api/sites', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sites WHERE user_id = $1 ORDER BY created_at ASC', [req.user.id])
    res.json(result.rows.map(dbSiteToObj))
  } catch (e) {
    console.error('get sites error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/sites', requireAuth, async (req, res) => {
  try {
    const { name, domain } = req.body
    if (!name || !domain) return res.status(400).json({ error: 'missing fields' })
    const id = uuidv4()
    const key = 'bw_live_' + crypto.randomBytes(16).toString('hex')
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0]
    const settings = { allowCrawlers: true, blockTor: false, blockVpn: false, challengeTtl: 24, challengeUi: {} }
    await pool.query(
      'INSERT INTO sites (id, user_id, name, domain, key, active, settings) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, req.user.id, name, cleanDomain, key, true, JSON.stringify(settings)]
    )
    res.json({ id, userId: req.user.id, name, domain: cleanDomain, key, createdAt: Date.now(), active: true, settings })
  } catch (e) {
    console.error('create site error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.put('/api/sites/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sites WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])
    if (result.rows.length === 0) return res.status(404).json({ error: 'not found' })
    const site = dbSiteToObj(result.rows[0])
    let rotatedKey = false
    if (req.body.name !== undefined) site.name = req.body.name
    if (req.body.domain !== undefined) {
      const newDomain = req.body.domain.replace(/^https?:\/\//, '').split('/')[0].trim()
      if (!newDomain) return res.status(400).json({ error: 'invalid domain' })
      if (newDomain !== site.domain) {
        site.domain = newDomain
        site.key = 'bw_live_' + crypto.randomBytes(16).toString('hex')
        rotatedKey = true
      }
    }
    if (req.body.settings !== undefined) {
      if (req.body.settings.challengeUi !== undefined) {
        req.body.settings.challengeUi = sanitizeChallengeUi(req.body.settings.challengeUi)
      }
      site.settings = req.body.settings
    }
    if (req.body.active !== undefined) site.active = req.body.active
    await pool.query(
      'UPDATE sites SET name = $1, settings = $2, active = $3, domain = $4, key = $5 WHERE id = $6',
      [site.name, JSON.stringify(site.settings), site.active, site.domain, site.key, site.id]
    )
    res.json({ ...site, rotatedKey })
  } catch (e) {
    console.error('update site error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id FROM sites WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])
    if (result.rows.length === 0) return res.status(404).json({ error: 'not found' })
    await pool.query('DELETE FROM sites WHERE id = $1', [req.params.id])
    res.json({ ok: true })
  } catch (e) {
    console.error('delete site error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/sites/:id/domain', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sites WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])
    if (result.rows.length === 0) return res.status(404).json({ error: 'not found' })
    const { domain } = req.body
    if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'missing domain' })
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].trim()
    if (!cleanDomain) return res.status(400).json({ error: 'invalid domain' })
    const newKey = 'bw_live_' + crypto.randomBytes(16).toString('hex')
    await pool.query('UPDATE sites SET domain = $1, key = $2 WHERE id = $3', [cleanDomain, newKey, req.params.id])
    res.json({ domain: cleanDomain, key: newKey })
  } catch (e) {
    console.error('domain change error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/sites/:id/rotate', requireAuth, async (req, res) => {  try {
    const result = await pool.query('SELECT * FROM sites WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])
    if (result.rows.length === 0) return res.status(404).json({ error: 'not found' })
    const newKey = 'bw_live_' + crypto.randomBytes(16).toString('hex')
    await pool.query('UPDATE sites SET key = $1 WHERE id = $2', [newKey, req.params.id])
    res.json({ key: newKey })
  } catch (e) {
    console.error('rotate key error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.get('/api/sites/:id/requests', requireAuth, async (req, res) => {
  try {
    const siteCheck = await pool.query('SELECT id FROM sites WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])
    if (siteCheck.rows.length === 0) return res.status(404).json({ error: 'not found' })
    const result = await pool.query('SELECT * FROM requests WHERE site_id = $1 ORDER BY ts DESC LIMIT 500', [req.params.id])
    res.json(result.rows.map(dbReqToObj))
  } catch (e) {
    console.error('get requests error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.get('/api/sites/:id/stats', requireAuth, async (req, res) => {
  try {
    const siteCheck = await pool.query('SELECT id FROM sites WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])
    if (siteCheck.rows.length === 0) return res.status(404).json({ error: 'not found' })
    const result = await pool.query(
      `SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE status = 'passed') AS passed,
        COUNT(*) FILTER (WHERE status = 'blocked') AS blocked,
        COUNT(*) FILTER (WHERE status = 'flagged') AS flagged
       FROM requests WHERE site_id = $1`,
      [req.params.id]
    )
    const row = result.rows[0]
    res.json({ total: Number(row.total), passed: Number(row.passed), blocked: Number(row.blocked), flagged: Number(row.flagged) })
  } catch (e) {
    console.error('get stats error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.get('/api/sites/:id/analytics', requireAuth, async (req, res) => {
  try {
    const siteCheck = await pool.query(
      'SELECT id FROM sites WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    )
    if (siteCheck.rows.length === 0) return res.status(404).json({ error: 'not found' })

    const now = Date.now()
    const days = parseInt(req.query.days) || 14
    const rangeMs = days * 86400000
    const sinceMs = now - rangeMs
    const priorSinceMs = now - rangeMs * 2

    // Daily breakdown
    const dailyResult = await pool.query(`
      SELECT
        TO_CHAR(TO_TIMESTAMP(ts/1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
        status,
        COUNT(*) AS count
      FROM requests
      WHERE site_id = $1 AND ts > $2
      GROUP BY day, status
      ORDER BY day ASC
    `, [req.params.id, sinceMs])

    // Hourly last 24h
    const hourlyResult = await pool.query(`
      SELECT
        TO_CHAR(TO_TIMESTAMP(ts/1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24') AS hour,
        status,
        COUNT(*) AS count
      FROM requests
      WHERE site_id = $1 AND ts > $2
      GROUP BY hour, status
      ORDER BY hour ASC
    `, [req.params.id, now - 86400000])

    // By detection type
    const detectedResult = await pool.query(`
      SELECT detected, COUNT(*) AS count
      FROM requests WHERE site_id = $1
      GROUP BY detected ORDER BY count DESC
    `, [req.params.id])

    // By country top 12
    const countryResult = await pool.query(`
      SELECT country, COUNT(*) AS count,
        COUNT(*) FILTER (WHERE status = 'passed') AS passed,
        COUNT(*) FILTER (WHERE status = 'blocked') AS blocked,
        COUNT(*) FILTER (WHERE status = 'flagged') AS flagged
      FROM requests WHERE site_id = $1
      GROUP BY country ORDER BY count DESC LIMIT 12
    `, [req.params.id])

    // Current period vs prior period
    const currentResult = await pool.query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE status = 'passed') AS passed,
        COUNT(*) FILTER (WHERE status = 'blocked') AS blocked,
        COUNT(*) FILTER (WHERE status = 'flagged') AS flagged
      FROM requests WHERE site_id = $1 AND ts > $2
    `, [req.params.id, sinceMs])

    const priorResult = await pool.query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE status = 'passed') AS passed,
        COUNT(*) FILTER (WHERE status = 'blocked') AS blocked,
        COUNT(*) FILTER (WHERE status = 'flagged') AS flagged
      FROM requests WHERE site_id = $1 AND ts > $2 AND ts <= $3
    `, [req.params.id, priorSinceMs, sinceMs])

    // All-time totals
    const totalsResult = await pool.query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE status = 'passed') AS passed,
        COUNT(*) FILTER (WHERE status = 'blocked') AS blocked,
        COUNT(*) FILTER (WHERE status = 'flagged') AS flagged
      FROM requests WHERE site_id = $1
    `, [req.params.id])

    // Peak day (all time)
    const peakResult = await pool.query(`
      SELECT
        TO_CHAR(TO_TIMESTAMP(ts/1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
        COUNT(*) AS count
      FROM requests WHERE site_id = $1
      GROUP BY day ORDER BY count DESC LIMIT 1
    `, [req.params.id])

    // Unique countries count
    const countriesResult = await pool.query(`
      SELECT COUNT(DISTINCT country) AS count FROM requests WHERE site_id = $1
    `, [req.params.id])

    const n = r => Number(r)

    res.json({
      totals: {
        total: n(totalsResult.rows[0].total),
        passed: n(totalsResult.rows[0].passed),
        blocked: n(totalsResult.rows[0].blocked),
        flagged: n(totalsResult.rows[0].flagged),
      },
      current: {
        total: n(currentResult.rows[0].total),
        passed: n(currentResult.rows[0].passed),
        blocked: n(currentResult.rows[0].blocked),
        flagged: n(currentResult.rows[0].flagged),
      },
      prior: {
        total: n(priorResult.rows[0].total),
        passed: n(priorResult.rows[0].passed),
        blocked: n(priorResult.rows[0].blocked),
        flagged: n(priorResult.rows[0].flagged),
      },
      daily: dailyResult.rows.map(r => ({ day: r.day, status: r.status, count: n(r.count) })),
      hourly: hourlyResult.rows.map(r => ({ hour: r.hour, status: r.status, count: n(r.count) })),
      byDetected: detectedResult.rows.map(r => ({ detected: r.detected, count: n(r.count) })),
      byCountry: countryResult.rows.map(r => ({
        country: r.country,
        count: n(r.count),
        passed: n(r.passed),
        blocked: n(r.blocked),
        flagged: n(r.flagged),
      })),
      peakDay: peakResult.rows[0] || null,
      uniqueCountries: n(countriesResult.rows[0].count),
      days,
    })
  } catch (e) {
    console.error('analytics error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/challenge/init', challengeLimiter, async (req, res) => {
  try {
    const { siteKey, returnUrl } = req.body
    const ua = req.headers['user-agent'] || ''
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || ''

    if (!siteKey) return res.status(400).json({ error: 'missing site key' })

    const siteResult = await pool.query('SELECT * FROM sites WHERE key = $1', [siteKey])
    if (siteResult.rows.length === 0) return res.status(404).json({ error: 'unknown site key' })
    const site = dbSiteToObj(siteResult.rows[0])
    if (!site.active) return res.status(403).json({ error: 'site inactive' })

    const challengeUi = sanitizeChallengeUi(site.settings.challengeUi || {})

    const country = lookupCountry(ip)
    const crawlerDetected = isCrawler(ua)
    const torDetected = looksLikeTor(ip)
    const headlessDetected = detectUaType(ua) === 'headless'
    const datacenterDetected = !torDetected && site.settings.blockVpn && detectDatacenter(ip)

    const allowedBots = site.settings.allowedBots || {}
    const allowedNames = allowedBots.names || []
    const allowedUaStrings = allowedBots.uaStrings || []
    const uaLower = ua.toLowerCase()
    const isAllowedBot = allowedNames.some(n => uaLower.includes(n.toLowerCase())) ||
      allowedUaStrings.some(s => uaLower.includes(s.toLowerCase()))

    if (isAllowedBot) {
      const token = jwt.sign({ siteId: site.id, type: 'pass', allowed: true }, SECRET, { expiresIn: TOKEN_TTL })
      await pool.query(
        'INSERT INTO requests (id, site_id, country, detected, status, ts, ua) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [uuidv4(), site.id, country, 'allowed', 'passed', Date.now(), ua]
      )
      return res.json({ token, skip: true, challengeUi })
    }

    let detectedType = 'N/A'
    if (torDetected) detectedType = 'tor'
    else if (crawlerDetected) detectedType = 'crawler'
    else if (headlessDetected) detectedType = 'headless'
    else if (datacenterDetected) detectedType = 'datacenter'

    if (crawlerDetected && site.settings.allowCrawlers) {
      const token = jwt.sign({ siteId: site.id, type: 'pass', crawler: true }, SECRET, { expiresIn: TOKEN_TTL })
      await pool.query(
        'INSERT INTO requests (id, site_id, country, detected, status, ts, ua) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [uuidv4(), site.id, country, 'crawler', 'passed', Date.now(), ua]
      )
      return res.json({ token, skip: true, challengeUi })
    }

    if (torDetected && site.settings.blockTor) {
      await pool.query(
        'INSERT INTO requests (id, site_id, country, detected, status, ts, ua) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [uuidv4(), site.id, country, 'tor', 'blocked', Date.now(), ua]
      )
      return res.status(403).json({ error: 'blocked', reason: 'tor' })
    }

    if (datacenterDetected) {
      await pool.query(
        'INSERT INTO requests (id, site_id, country, detected, status, ts, ua) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [uuidv4(), site.id, country, 'datacenter', 'blocked', Date.now(), ua]
      )
      return res.status(403).json({ error: 'blocked', reason: 'datacenter' })
    }

    const bucket = rateBuckets.get(ip) || { count: 0, reset: Date.now() + 60000 }
    if (Date.now() > bucket.reset) { bucket.count = 0; bucket.reset = Date.now() + 60000 }
    bucket.count++
    rateBuckets.set(ip, bucket)
    if (bucket.count > 15) {
      return res.status(429).json({ error: 'rate limited', retryAfter: Math.ceil((bucket.reset - Date.now()) / 1000) })
    }

    const challengeId = uuidv4()
    const difficulty = (torDetected || headlessDetected) ? 6 : 4
    challenges.set(challengeId, {
      siteId: site.id, siteKey, returnUrl, difficulty,
      ip, ua, country, detectedType,
      expires: Date.now() + 120000,
      torDetected, crawlerDetected, headlessDetected
    })
    setTimeout(() => challenges.delete(challengeId), 120000)

    res.json({ challengeId, difficulty, challengeUi })
  } catch (e) {
    console.error('challenge init error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/challenge/verify', challengeLimiter, async (req, res) => {
  try {
    const { challengeId, nonce, elapsed } = req.body
    const ch = challenges.get(challengeId)
    if (!ch || Date.now() > ch.expires) return res.status(410).json({ error: 'challenge expired' })
    challenges.delete(challengeId)

    const siteResult = await pool.query('SELECT * FROM sites WHERE id = $1', [ch.siteId])
    if (siteResult.rows.length === 0) return res.status(404).json({ error: 'site not found' })
    const site = dbSiteToObj(siteResult.rows[0])

    const hash = crypto.createHash('sha256').update(challengeId + nonce).digest('hex')
    const prefix = '0'.repeat(ch.difficulty)
    const valid = hash.startsWith(prefix)
    const tooFast = elapsed < 200
    const suspicious = tooFast || !valid

    const detected = ch.detectedType || 'N/A'
    const status = suspicious ? (ch.headlessDetected ? 'blocked' : 'flagged') : 'passed'

    await pool.query(
      'INSERT INTO requests (id, site_id, country, detected, status, ts, ua) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [uuidv4(), ch.siteId, ch.country || 'Unknown', detected, status, Date.now(), ch.ua]
    )

    if (suspicious) return res.status(403).json({ error: 'challenge failed' })

    const ttl = (site.settings.challengeTtl || 24) * 3600
    const token = jwt.sign({ siteId: ch.siteId, type: 'pass' }, SECRET, { expiresIn: ttl })
    res.json({ token })
  } catch (e) {
    console.error('challenge verify error', e.message)
    res.status(500).json({ error: 'server error' })
  }
})

app.post('/api/challenge/check', apiLimiter, async (req, res) => {
  try {
    const { token, siteKey } = req.body
    if (!token || !siteKey) return res.status(400).json({ valid: false })
    const siteResult = await pool.query('SELECT id FROM sites WHERE key = $1', [siteKey])
    if (siteResult.rows.length === 0) return res.json({ valid: false })
    const siteId = siteResult.rows[0].id
    const payload = jwt.verify(token, SECRET)
    res.json({ valid: payload.siteId === siteId })
  } catch {
    res.json({ valid: false })
  }
})

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) AS count FROM users')
    const sites = await pool.query('SELECT COUNT(*) AS count FROM sites')
    const requests = await pool.query('SELECT COUNT(*) AS count FROM requests')
    const recentReqs = await pool.query('SELECT COUNT(*) AS count FROM requests WHERE ts > $1', [Date.now() - 86400000])
    res.json({
      users: Number(users.rows[0].count),
      sites: Number(sites.rows[0].count),
      requests: Number(requests.rows[0].count),
      requestsToday: Number(recentReqs.rows[0].count)
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.name, u.created_at,
        COUNT(DISTINCT s.id) AS site_count,
        COUNT(r.id) AS request_count
      FROM users u
      LEFT JOIN sites s ON s.user_id = u.id
      LEFT JOIN requests r ON r.site_id = s.id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `)
    res.json(result.rows.map(row => ({
      id: row.id,
      email: row.email,
      name: row.name,
      createdAt: Number(row.created_at),
      siteCount: Number(row.site_count),
      requestCount: Number(row.request_count)
    })))
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.get('/api/admin/sites', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, u.email AS user_email, u.name AS user_name,
        COUNT(r.id) AS request_count
      FROM sites s
      JOIN users u ON u.id = s.user_id
      LEFT JOIN requests r ON r.site_id = s.id
      GROUP BY s.id, u.email, u.name
      ORDER BY s.created_at DESC
    `)
    res.json(result.rows.map(row => ({
      ...dbSiteToObj(row),
      userEmail: row.user_email,
      userName: row.user_name,
      requestCount: Number(row.request_count)
    })))
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id])
    res.json({ ok: true })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── blog (public) ──────────────────────────────────────────────────────────────

app.get('/api/blog', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, title, slug, excerpt, published_at FROM blog_posts ORDER BY published_at DESC'
    )
    res.json(result.rows.map(r => ({
      id: r.id, title: r.title, slug: r.slug,
      excerpt: r.excerpt, publishedAt: Number(r.published_at)
    })))
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/blog/:slug', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM blog_posts WHERE slug = $1', [req.params.slug])
    if (!result.rows.length) return res.status(404).json({ error: 'not found' })
    const r = result.rows[0]
    res.json({ id: r.id, title: r.title, slug: r.slug, content: r.content, excerpt: r.excerpt, publishedAt: Number(r.published_at) })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ── blog (admin) ────────────────────────────────────────────────────────────────

app.post('/api/admin/blog', requireAdmin, async (req, res) => {
  try {
    const { title, content } = req.body
    if (!title || !content) return res.status(400).json({ error: 'title and content required' })
    const slug = title.toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').slice(0, 80)
    const excerpt = content.replace(/[#*`\[\]()>_~]/g, '').replace(/\n+/g, ' ').trim().slice(0, 220)
    const now = Date.now()
    const id = uuidv4()
    await pool.query(
      'INSERT INTO blog_posts (id, title, slug, content, excerpt, published_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, title.trim(), slug, content.trim(), excerpt, now]
    )
    res.json({ id, slug, publishedAt: now })
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'a post with a similar title already exists' })
    res.status(500).json({ error: e.message })
  }
})

app.delete('/api/admin/blog/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM blog_posts WHERE id = $1', [req.params.id])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ── rss feed ────────────────────────────────────────────────────────────────────

const BASE_URL = process.env.BASE_URL || 'https://brickwall.onrender.com'

app.get('/rss.xml', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM blog_posts ORDER BY published_at DESC LIMIT 50'
    )
    const esc = s => String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;')
    const fmtRfc = ts => new Date(Number(ts)).toUTCString()

    const items = result.rows.map(r => `
    <item>
      <title>${esc(r.title)}</title>
      <link>${BASE_URL}/blog.html?post=${esc(r.slug)}</link>
      <guid isPermaLink="true">${BASE_URL}/blog.html?post=${esc(r.slug)}</guid>
      <pubDate>${fmtRfc(r.published_at)}</pubDate>
      <description>${esc(r.excerpt)}</description>
      <content:encoded><![CDATA[${r.content}]]></content:encoded>
    </item>`).join('')

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:content="http://purl.org/rss/1.0/modules/content/"
  xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>brickwall blog</title>
    <link>${BASE_URL}/blog.html</link>
    <description>updates, guides, and notes from the brickwall team</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
    <atom:link href="${BASE_URL}/rss.xml" rel="self" type="application/rss+xml"/>
    ${items}
  </channel>
</rss>`

    res.setHeader('Content-Type', 'application/rss+xml; charset=utf-8')
    res.send(xml)
  } catch (e) { res.status(500).send('<!-- error: ' + e.message + ' -->') }
})

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'))
})

initDb().then(() => {
  app.listen(PORT, () => console.log(`brickwall running on :${PORT}`))
}).catch(e => {
  console.error('failed to init db:', e.message)
  process.exit(1)
})
