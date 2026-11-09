import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const source = resolve(root, 'dist')
const destination = resolve(root, '../src/bt_api_gateway/web/static')
await readFile(resolve(source, 'index.html'))
await mkdir(dirname(destination), { recursive: true })
await rm(destination, { recursive: true, force: true })
await cp(source, destination, { recursive: true })

// Ship installed production dependency license notices alongside the bundle.
const packages = JSON.parse(await readFile(resolve(source, 'THIRD_PARTY_MODULES.json'), 'utf8'))
const notices = []
for (const name of packages) {
  const entry = `node_modules/${name}`
  const directory = resolve(root, entry)
  const files = await readdir(directory)
  const license = files.find(name => /^(license|copying)(\.|$)/i.test(name))
  if (!license) throw new Error(`missing installed license: ${entry}`)
  const info = JSON.parse(await readFile(resolve(directory, 'package.json'), 'utf8'))
  notices.push(`\n--- ${entry} (${info.version ?? 'unknown'}) ---\n${await readFile(resolve(directory, license), 'utf8')}\n`)
}
await writeFile(resolve(destination, 'THIRD_PARTY_NOTICES.txt'), notices.join(''), 'utf8')
