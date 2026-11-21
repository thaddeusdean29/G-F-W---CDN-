import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发时后端跑在 :8080（见 internal/config/model.go 的默认 ListenAddr）。
// /api/v2 全部转发过去，Cookie 走同源不受影响。
export default defineConfig({
  // 生产环境挂在 /console/ 下（根路径 / 由 cdnpanel 跳转到 /console/），
  // 开发环境（vite dev server 本身跑在 :5173 根路径）用不到这个 base。
  base: process.env.NODE_ENV === 'production' ? '/console/' : '/',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api/v2': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    // 构建产物直接落到 ../web/console_dist，让 web/web.go 的 go:embed 能拿到，
    // cdnpanel 编译时就把整套前端一起打进二进制，不用再单独分发 dist 目录。
    outDir: '../web/console_dist',
    emptyOutDir: true,
  },
})
