import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { enrollRoute } from './routes/enroll.js'
import { challengeRoute } from './routes/challenge.js'
import { verifyRoute } from './routes/verify.js'

const app = new Hono()

app.use('*', cors())

app.get('/', (c) => c.json({ name: 'biokey-server', version: '0.1.0' }))

enrollRoute(app)
challengeRoute(app)
verifyRoute(app)

const port = process.env.PORT ?? 3000
console.log(`biokey-server running on port ${port}`)

export default {
	port,
	fetch: app.fetch
}
