const express = require('express')
const cors = require('cors')
const nodemailer = require('nodemailer')
const helmet = require('helmet')
const xss = require('xss')
const { RateLimiterMemory } = require('rate-limiter-flexible')

require('dotenv').config()

const app = express()
const PORT = process.env.PORT || 3001

// security
app.use(helmet())
app.use(express.json({ limit: '6kb' })) // limit payloads
app.use(express.urlencoded({ extended: true }))

const allowedOrigins = (process.env.CORS_ORIGIN).split(',').map(s => s.trim())

const corsOptions = {
  origin: function (origin, callback) {
    // allow non-browser tools like curl where origin is undefined/null
    if (!origin) return callback(null, true)

    // allow exact match
    if (allowedOrigins.includes(origin)) return callback(null, true)

    // otherwise block
    callback(new Error('CORS policy: origin not allowed'), false)
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type'],
  optionsSuccessStatus: 204,
}

app.use(cors(corsOptions))
// ensure preflight replies are handled
app.options('*', cors(corsOptions))

// simple rate limiter
const rateLimiter = new RateLimiterMemory({
  points: parseInt(process.env.RATE_LIMIT_POINTS || '6', 10), // requests
  duration: parseInt(process.env.RATE_LIMIT_WINDOW || '60', 10), // per seconds
})

// helpers
function sanitize(input = '') {
  // basic cleaning - since we already have server-side validation; xss can sanitize HTML
  return xss(String(input || '').trim()).slice(0, 5000)
}

function buildHtmlEmail({ name, email, message }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<style>
  body{font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0}
  .email-container{background:#fff;padding:20px;max-width:600px;margin:20px auto;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);text-align:center}
  h2{color:#333}
  p{line-height:1.6;color:#555}
  .form-data{margin:20px 0}
  .form-data label{font-weight:700;display:block;margin-bottom:5px;color:#333}
  .form-data span{display:block;padding:10px;background:#f9f9f9;border-radius:5px;color:#333;word-wrap:break-word}
  .footer{text-align:center;font-size:12px;color:#999;margin-top:30px}
</style></head><body>
  <div class="email-container">
    <h2>New Contact Form Submission</h2>
    <p>You have received a new message from the contact form on your Portfolio. Here are the details:</p>
    <div class="form-data"><label>Name:</label><span>${name}</span></div>
    <div class="form-data"><label>Email:</label><span>${email}</span></div>
    <div class="form-data"><label>Message:</label><span>${message}</span></div>
    <p>Be sure to follow up with this inquiry as soon as possible.</p>
    <div class="footer"><p>&copy; Sharun - Portfolio</p></div>
  </div>
</body></html>`
}

// transport factory (create once)
function createTransporter() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    throw new Error('Missing SMTP env vars')
  }
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465, // true for 465
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  })
}

const transporter = (() => {
  try {
    return createTransporter()
  } catch (err) {
    console.error('SMTP not configured yet:', err.message)
    return null
  }
})()

// health
app.get('/api/health', (req, res) => res.json({ ok: true }))

// contact endpoint
app.post('/api/contact', async (req, res) => {
  try {
    // rate limit by IP
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown'

    await rateLimiter.consume(ip)

    const { name, email, message, _hp } = req.body || {}

    // honeypot spam trap
    if (_hp) {
      return res.status(400).json({ error: 'spam' })
    }

    // basic validation
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'missing_fields' })
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(String(email))) {
      return res.status(400).json({ error: 'invalid_email' })
    }

    // sanitize
    const safeName = sanitize(name).slice(0, 200)
    const safeEmail = sanitize(email).slice(0, 200)
    const safeMessage = sanitize(message).slice(0, 5000)

    if (!transporter) {
      console.error('Transporter not ready')
      return res.status(500).json({ error: 'server_misconfigured' })
    }

    const html = buildHtmlEmail({ name: safeName, email: safeEmail, message: safeMessage })
    const mailOptions = {
      from: process.env.SENDER_EMAIL || process.env.SMTP_USER,
      to: process.env.RECEIVER_EMAIL,
      replyTo: safeEmail,
      subject: `Portfolio contact from ${safeName}`,
      html,
    }

    await transporter.sendMail(mailOptions)
    return res.status(200).json({ ok: true })
  } catch (err) {
    if (err instanceof Error && err.msBeforeNext) {
      // rate-limiter-flexible returns msBeforeNext on consumed errors
      return res.status(429).json({ error: 'rate_limited' })
    }
    console.error('Contact send failed:', err)
    return res.status(500).json({ error: 'failed_to_send' })
  }
})

const server = app.listen(PORT, () => {
  console.log(`Contact API running on port ${PORT}`)
})

// graceful shutdown
process.on('SIGINT', () => server.close(() => process.exit(0)))
process.on('SIGTERM', () => server.close(() => process.exit(0)))