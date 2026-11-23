import handler from './[...path].js'

export default function firewall(req, res) {
  req.query = { ...req.query, path: ['firewall'] }
  return handler(req, res)
}
