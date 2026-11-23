const scans = []
let firewallEnabled = true

const rules = [
  [/ignore (all |previous |prior )?(instructions|rules)|disregard (the )?(system|above)/i, 'Critical', 'Instruction override', 'The content attempts to override trusted instructions.'],
  [/system prompt|reveal (your |the )?(prompt|instructions)|developer message/i, 'High', 'Prompt extraction', 'The content requests protected prompt or system information.'],
  [/send .*?(email|file|data)|share .*?(externally|secret)|upload .*?(data|document)/i, 'High', 'Unauthorized action', 'The content asks an agent to take an external action.'],
  [/bypass (security|approval|policy)|disable (security|firewall)/i, 'Critical', 'Security control evasion', 'The content attempts to bypass a security control.']
]

function analyze(content, type = 'Text', name = 'Pasted content') {
  const found = rules.find(([pattern]) => pattern.test(content))
  const severity = found?.[1] || 'Low'
  const riskScore = { Low: 12, Medium: 46, High: 73, Critical: 94 }[severity]
  const scan = {
    id: `SCN-${9001 + scans.length}`, name, type, risk: severity,
    status: severity === 'Low' ? 'Safe' : 'Blocked', date: new Date().toLocaleString(),
    riskScore, severity, category: found?.[2] || 'No prompt injection detected',
    explanation: found ? 'PromptShield detected a suspicious instruction pattern in untrusted content.' : 'No known indirect prompt injection pattern was found.',
    evidence: found ? content.match(found[0])?.[0] : 'No suspicious excerpt detected.',
    whyFlagged: found?.[3] || 'The content did not match a high-risk instruction pattern.',
    recommendation: severity === 'Low' ? 'Allow content with normal monitoring.' : 'Block the content and review it before use.',
    method: 'Pattern and context inspection'
  }
  scans.unshift(scan)
  return scan
}

export default function handler(req, res) {
  // Vercel's catch-all route may not populate req.query.path for a Vite app,
  // so derive the endpoint from the request URL as the reliable fallback.
  const requestPath = new URL(req.url, 'https://promptshield.local').pathname
  const path = requestPath.replace(/^\/api/, '') || '/'
  if (req.method === 'GET' && path === '/dashboard') return res.status(200).json({ totalScans: scans.length, threatsDetected: scans.filter(s => s.risk !== 'Low').length, threatsBlocked: scans.filter(s => s.status === 'Blocked').length, safeDocuments: scans.filter(s => s.status === 'Safe').length })
  if (req.method === 'GET' && path === '/scans') return res.status(200).json({ records: scans })
  if (req.method === 'POST' && path === '/scans/text') {
    const content = req.body?.content
    return content?.trim() ? res.status(201).json(analyze(content)) : res.status(400).json({ message: 'Content is required.' })
  }
  if (req.method === 'POST' && path === '/scans/url') {
    const url = req.body?.url
    return /^https?:\/\//i.test(url || '') ? res.status(201).json(analyze(url, 'URL', url)) : res.status(400).json({ message: 'Enter a valid http(s) URL.' })
  }
  if (req.method === 'POST' && path === '/scans/upload') return res.status(201).json(analyze('Uploaded file', 'Document', 'Uploaded file'))
  if (req.method === 'PATCH' && path === '/firewall') { firewallEnabled = Boolean(req.body?.enabled); return res.status(200).json({ enabled: firewallEnabled }) }
  if (path === '/folder-monitor') return res.status(501).json({ message: 'Windows folder monitoring runs only on the local desktop server, not Vercel.' })
  return res.status(404).json({ message: `No route for ${req.method} ${path}` })
}
