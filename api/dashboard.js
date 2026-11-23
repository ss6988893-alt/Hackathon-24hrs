import handler from './[...path].js'

export default function dashboard(req, res) {
  req.query = { ...req.query, path: ['dashboard'] }
  return handler(req, res)
}
