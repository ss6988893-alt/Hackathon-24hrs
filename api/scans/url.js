import handler from '../[...path].js'

export default function urlScan(req, res) {
  req.query = { ...req.query, path: ['scans', 'url'] }
  return handler(req, res)
}
