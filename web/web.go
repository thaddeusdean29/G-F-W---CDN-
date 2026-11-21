package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// console_dist 对应 vue/dist（vite.config.ts 把 build.outDir 指到这里），由
// `npm run build` 生成后与 cdnpanel 一起编译进同一个二进制。仓库里保留的
// index.html 只是个占位提示页——go:embed 要求目录在编译期存在且非空，没跑过
// npm run build 时也得让 go build 能过；真正构建后 emptyOutDir 会把占位文件覆盖掉。
//
// all: 不能省：不带它 go:embed 会跳过 _ 开头的文件，而 Vite 会产出
// _plugin-vue_export-helper-*.js 这类 chunk，漏掉后懒加载路由全挂、页面空白。
//
//go:embed all:console_dist
var consoleDistRaw embed.FS

func consoleDistFS() fs.FS {
	sub, err := fs.Sub(consoleDistRaw, "console_dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// ConsoleHandler 在 /console/ 下服务编译进二进制的 Vue SPA。命中不到的子路径统一
// 回退到 index.html，让 vue-router 的 history 模式（浏览器直接刷新 /console/domains
// 这类前端路由）能正常工作，而不是被 http.FileServer 当成 404。
func ConsoleHandler() http.Handler {
	fsys := consoleDistFS()
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/console"), "/")
		if upath != "" {
			if _, err := fs.Stat(fsys, upath); err != nil {
				upath = ""
			}
		}
		// upath == "" 时把路径设为根目录 "/" 而不是 "/index.html"：net/http 的
		// FileServer 一看到请求路径以 "/index.html" 结尾就会 301 到 "./" 做规范化，
		// 在这里会变成对 /console/ 自身的死循环重定向，只能靠让它落到目录索引来避开。
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + upath
		fileServer.ServeHTTP(w, r2)
	})
}
