import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { existsSync, watch, readFile } from 'node:fs'

// The development server includes the local API, so `npm run dev` always
// starts a working dashboard and scanner together.
const scans = []
let firewallEnabled = true
let monitoredFolder = ''
let folderWatcher = null
const threatRules = [
  [/ignore (all |previous |prior )?(instructions|rules)|disregard (the )?(system|above)/i, 'Critical', 'Instruction override', 'The content attempts to override trusted instructions.'],
  [/system prompt|reveal (your |the )?(prompt|instructions)|developer message/i, 'High', 'Prompt extraction', 'The content requests protected prompt or system information.'],
  [/send .*?(email|file|data)|share .*?(externally|secret)|upload .*?(data|document)/i, 'High', 'Unauthorized action', 'The content asks an agent to take an external action.'],
  [/bypass (security|approval|policy)|disable (security|firewall)/i, 'Critical', 'Security control evasion', 'The content attempts to bypass a security control.']
]
const readBody = (req) => new Promise((resolve, reject) => { let raw = ''; req.setEncoding('utf8'); req.on('data', part => raw += part); req.on('end', () => resolve(raw)); req.on('error', reject) })
const reply = (res, code, data) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(data)) }
function scan(content, type = 'Text', name = 'Pasted content') {
  const found = threatRules.find(([rule]) => rule.test(content)); const severity = found?.[1] || 'Low'; const score = { Low: 12, Medium: 46, High: 73, Critical: 94 }[severity]
  const item = { id: `SCN-${9001 + scans.length}`, name, type, risk: severity, status: severity === 'Low' ? 'Safe' : 'Blocked', date: new Date().toLocaleString(), riskScore: score, severity, category: found?.[2] || 'No prompt injection detected', explanation: found ? 'PromptShield detected a suspicious instruction pattern in untrusted content.' : 'No known indirect prompt injection pattern was found.', evidence: found ? content.match(found[0])?.[0] : 'No suspicious excerpt detected.', whyFlagged: found?.[3] || 'The content did not match a high-risk instruction pattern.', recommendation: severity === 'Low' ? 'Allow content with normal monitoring.' : 'Block the content and review it before use.', method: 'Pattern and context inspection' }
  scans.unshift(item); return item
}
function localApi() { return { name: 'promptshield-local-api', configureServer(server) { server.middlewares.use('/api', async (req, res, next) => { try { if (req.method === 'GET' && req.url === '/dashboard') return reply(res, 200, { totalScans: scans.length, threatsDetected: scans.filter(s => s.risk !== 'Low').length, threatsBlocked: scans.filter(s => s.status === 'Blocked').length, safeDocuments: scans.filter(s => s.status === 'Safe').length }); if (req.method === 'GET' && req.url === '/scans') return reply(res, 200, { records: scans }); if (req.method === 'GET' && req.url === '/folder-monitor') return reply(res, 200, { active: Boolean(folderWatcher), folder: monitoredFolder }); if (req.method === 'POST' && req.url === '/folder-monitor') { const { folder } = JSON.parse(await readBody(req)); if (!existsSync(folder)) return reply(res, 400, { message: 'That Windows folder does not exist or cannot be read.' }); folderWatcher?.close(); monitoredFolder = folder; folderWatcher = watch(folder, async (_event, filename) => { if (!filename) return; try { const fullPath = `${monitoredFolder}\\${filename}`; const content = await readFile(fullPath, 'utf8'); scan(content, 'Folder file', filename) } catch {} }); return reply(res, 201, { active: true, folder }) } if (req.method === 'DELETE' && req.url === '/folder-monitor') { folderWatcher?.close(); folderWatcher = null; monitoredFolder = ''; return reply(res, 200, { active: false }) } if (req.method === 'POST' && req.url === '/scans/text') { const { content } = JSON.parse(await readBody(req)); return content?.trim() ? reply(res, 201, scan(content)) : reply(res, 400, { message: 'Content is required.' }) } if (req.method === 'POST' && req.url === '/scans/url') { const { url } = JSON.parse(await readBody(req)); if (!/^https?:\/\//i.test(url || '')) return reply(res, 400, { message: 'Enter a valid http(s) URL.' }); return reply(res, 201, scan(url, 'URL', url)) } if (req.method === 'POST' && req.url === '/scans/upload') return reply(res, 201, scan(await readBody(req), 'Document', 'Uploaded file')); if (req.method === 'PATCH' && req.url === '/firewall') { firewallEnabled = Boolean(JSON.parse(await readBody(req)).enabled); return reply(res, 200, { enabled: firewallEnabled }) } reply(res, 404, { message: `No route for ${req.method} ${req.url}` }) } catch (error) { reply(res, 400, { message: error.message || 'Invalid API request.' }) } }) } } }
export default defineConfig({ plugins: [react(), localApi()] })
