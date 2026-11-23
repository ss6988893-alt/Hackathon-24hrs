import handler from '../[...path].js'

export default function textScan(req, res) {
  req.query = { ...req.query, path: ['scans', 'text'] }
  return handler(req, res)
}
