import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue(), {
    name: 'gateway-bundled-modules',
    generateBundle(_, bundle) {
      const packages = new Set<string>()
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== 'chunk') continue
        for (const [id, info] of Object.entries(chunk.modules)) {
          const marker = '/node_modules/'
          const index = id.lastIndexOf(marker)
          if (index < 0 || info.renderedLength === 0) continue
          const parts = id.slice(index + marker.length).split('/')
          packages.add(parts[0].startsWith('@') ? `${parts[0]}/${parts[1]}` : parts[0])
        }
      }
      this.emitFile({ type: 'asset', fileName: 'THIRD_PARTY_MODULES.json', source: JSON.stringify([...packages].sort(), null, 2) + '\n' })
    }
  }],
  server: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:8000' } },
  preview: { host: '127.0.0.1' }
})
