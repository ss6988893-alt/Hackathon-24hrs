import { spawn } from 'node:child_process'

const api = spawn(process.execPath, ['api-server.mjs'], { stdio: 'inherit' })
const vite = spawn(process.execPath, ['node_modules/vite/bin/vite.js'], { stdio: 'inherit' })
const stop = () => { api.kill(); vite.kill(); process.exit() }
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
