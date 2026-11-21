package apiv2

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// 网站图标（favicon）：管理员上传，存在 platform_assets 表，GET /api/v2/branding/favicon 公开读取。
// 上传体就是图片原始字节（不走 multipart）。格式按文件内容判断，不信任客户端给的 Content-Type；
// 只收位图格式，不收 SVG——SVG 能带脚本，和面板同源返回会变成存储型 XSS。
// ---------------------------------------------------------------------------

const (
	faviconPath    = "/api/v2/branding/favicon"
	faviconAsset   = "favicon"
	faviconMaxSize = 256 << 10
)

var faviconTypes = map[string]bool{
	"image/png":    true,
	"image/x-icon": true,
	"image/jpeg":   true,
	"image/gif":    true,
	"image/webp":   true,
}

// sniffFavicon 返回图片的 MIME 类型；不是允许的格式时返回空串。
func sniffFavicon(data []byte) string {
	mime := http.DetectContentType(data)
	if faviconTypes[mime] {
		return mime
	}
	return ""
}

func faviconSHA(ctx context.Context, db *sql.DB) (string, error) {
	var sha string
	err := db.QueryRowContext(ctx, `SELECT sha256 FROM platform_assets WHERE name = ?`, faviconAsset).Scan(&sha)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return sha, err
}

// faviconHandler 处理公开的 GET /api/v2/branding/favicon。
func faviconHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var mime, sha string
		var data []byte
		err := db.QueryRowContext(r.Context(),
			`SELECT mime, sha256, data FROM platform_assets WHERE name = ?`, faviconAsset).Scan(&mime, &sha, &data)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			WriteError(w, err)
			return
		}
		etag := `"` + sha + `"`
		hdr := w.Header()
		hdr.Set("Content-Type", mime)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Content-Security-Policy", "default-src 'none'")
		hdr.Set("ETag", etag)
		// 地址里带的版本号和当前内容一致时可以长期缓存；换图标后版本号变了，浏览器会重新取。
		if v := r.URL.Query().Get("v"); v != "" && strings.HasPrefix(sha, v) {
			hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			hdr.Set("Cache-Control", "no-cache")
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	}
}

// adminFaviconHandler 处理 PUT/DELETE /api/v2/admin/settings/favicon（需管理员会话 + CSRF）。
type adminFaviconHandler struct{ db *sql.DB }

func (h *adminFaviconHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		h.put(w, r)
	case http.MethodDelete:
		if _, err := h.db.ExecContext(r.Context(), `DELETE FROM platform_assets WHERE name = ?`, faviconAsset); err != nil {
			WriteError(w, err)
			return
		}
		h.respond(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *adminFaviconHandler) put(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, faviconMaxSize+1))
	if err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体读取失败"))
		return
	}
	if len(data) == 0 {
		WriteError(w, fieldError("favicon", "请选择图标文件"))
		return
	}
	if len(data) > faviconMaxSize {
		WriteError(w, fieldError("favicon", "图标不能超过 256 KB"))
		return
	}
	mime := sniffFavicon(data)
	if mime == "" {
		WriteError(w, fieldError("favicon", "只支持 ICO、PNG、JPG、GIF、WebP 格式"))
		return
	}
	sum := sha256.Sum256(data)
	if _, err := h.db.ExecContext(r.Context(), `INSERT INTO platform_assets (name, mime, sha256, data) VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE mime = VALUES(mime), sha256 = VALUES(sha256), data = VALUES(data)`,
		faviconAsset, mime, hex.EncodeToString(sum[:]), data); err != nil {
		WriteError(w, err)
		return
	}
	h.respond(w, r)
}

// respond 返回更新后的完整品牌信息，前端直接用它刷新页面上的图标。
func (h *adminFaviconHandler) respond(w http.ResponseWriter, r *http.Request) {
	v, err := loadBrandingView(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
