import { createServer } from 'node:http'
import { readFile, stat } from 'node:fs/promises'
import { createReadStream } from 'node:fs'
import { extname, join, normalize } from 'node:path'

const port = Number(process.env.PORT || 8787)
const scans = []
let firewallEnabled = true

const patterns = [
  { re: /ignore (all |previous |prior )?(instructions|rules)|disregard (the )?(system|above)/i, severity: 'Critical', category: 'Instruction override', why: 'The content attempts to override trusted instructions.' },
  { re: /system prompt|reveal (your |the )?(prompt|instructions)|developer message/i, severity: 'High', category: 'Prompt extraction', why: 'The content requests protected prompt or system information.' },
  { re: /send .*?(email|file|data)|share .*?(externally|secret)|upload .*?(data|document)/i, severity: 'High', category: 'Unauthorized action', why: 'The content asks an agent to take an external action.' },
  { re: /bypass (security|approval|policy)|disable (security|firewall)/i, severity: 'Critical', category: 'Security control evasion', why: 'The content attempts to bypass a security control.' }
]
const riskFor = { Low: 12, Medium: 46, High: 73, Critical: 94 }
function analyze(content, type = 'Text', name = 'Pasted content') {
  const match = patterns.find(({ re }) => re.test(content))
  const severity = match?.severity || 'Low'
  const evidence = match ? content.match(match.re)?.[0] : ''
  const item = {
    id: `SCN-${String(9000 + scans.length + 1)}`,
    name, type, risk: severity, status: severity === 'Low' ? 'Safe' : 'Blocked',
    date: new Date().toLocaleString(), riskScore: riskFor[severity], severity,
    category: match?.category || 'No prompt injection detected',
    explanation: match ? 'PromptShield detected a suspicious instruction pattern in untrusted content.' : 'No known indirect prompt injection pattern was found.',
    evidence: evidence || 'No suspicious excerpt detected.', whyFlagged: match?.why || 'The content did not match a high-risk instruction pattern.',
    recommendation: severity === 'Low' ? 'Allow content with normal monitoring.' : 'Block the content and review it before use.',
    method: 'Pattern and context inspection'
  }
  scans.unshift(item)
  return item
}
function send(res, status, payload) { res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }); res.end(JSON.stringify(payload)) }
function body(req) { return new Promise((resolve, reject) => { let raw = ''; req.setEncoding('utf8'); req.on('data', c => raw += c); req.on('end', () => resolve(raw)); req.on('error', reject) }) }
const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {})
  const url = new URL(req.url, `http://${req.headers.host}`)
  if (req.method === 'GET' && url.pathname === '/dashboard') {
    const threats = scans.filter(s => s.risk !== 'Low')
    return send(res, 200, { totalScans: scans.length, threatsDetected: threats.length, threatsBlocked: threats.filter(s => s.status === 'Blocked').length, safeDocuments: scans.filter(s => s.status === 'Safe').length })
  }
  if (req.method === 'GET' && url.pathname === '/scans') return send(res, 200, { records: scans })
  if (req.method === 'POST' && url.pathname === '/scans/text') {
    try { const { content } = JSON.parse(await body(req)); if (!content?.trim()) return send(res, 400, { message: 'Content is required.' }); return send(res, 201, analyze(content, 'Text')) } catch { return send(res, 400, { message: 'Invalid scan request.' }) }
  }
  if (req.method === 'POST' && url.pathname === '/scans/upload') {
    const raw = await body(req); const content = raw.replace(/[-\w]+\r?\n(?:Content-[^\n]+\n)*\r?\n/g, ' ').slice(0, 50000)
    return send(res, 201, analyze(content || 'Uploaded file', req.headers['content-type']?.includes('eml') ? 'Email' : 'Document', 'Uploaded file'))
  }
  if (req.method === 'PATCH' && url.pathname === '/firewall') {
    try { firewallEnabled = Boolean(JSON.parse(await body(req)).enabled); return send(res, 200, { enabled: firewallEnabled }) } catch { return send(res, 400, { message: 'Invalid firewall setting.' }) }
  }
  send(res, 404, { message: `No route for ${req.method} ${url.pathname}` })
})
server.listen(port, '127.0.0.1', () => console.log(`PromptShield API running at http://127.0.0.1:${port}`))
