import handler from '../[...path].js'

export default function uploadScan(req, res) {
  req.query = { ...req.query, path: ['scans', 'upload'] }
  return handler(req, res)
}
