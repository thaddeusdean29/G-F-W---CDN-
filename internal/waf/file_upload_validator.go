package waf

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// FileUploadValidator 文件上传魔术字节验证器。
// 检测上传文件的真实类型（通过文件头魔术字节），防止伪装的恶意文件。
type FileUploadValidator struct {
	maxSize int64 // 最大文件大小（字节）
}

// NewFileUploadValidator 创建文件上传验证器。
func NewFileUploadValidator(maxSize int64) *FileUploadValidator {
	if maxSize <= 0 {
		maxSize = 32 << 20 // 默认 32MB
	}
	return &FileUploadValidator{
		maxSize: maxSize,
	}
}

// magicBytes 定义常见文件类型的魔术字节签名。
var magicBytes = []struct {
	mime   string
	magic  []byte
	offset int
}{
	// 图片
	{"image/jpeg", []byte{0xFF, 0xD8, 0xFF}, 0},
	{"image/png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0},
	{"image/gif", []byte{0x47, 0x49, 0x46, 0x38}, 0}, // GIF87a / GIF89a
	{"image/webp", []byte{0x52, 0x49, 0x46, 0x46}, 0}, // RIFF (需额外检查 WEBP 标记)
	{"image/bmp", []byte{0x42, 0x4D}, 0},
	{"image/tiff", []byte{0x49, 0x49, 0x2A, 0x00}, 0}, // Intel 字节序
	{"image/tiff", []byte{0x4D, 0x4D, 0x00, 0x2A}, 0}, // Motorola 字节序

	// 文档
	{"application/pdf", []byte{0x25, 0x50, 0x44, 0x46}, 0}, // %PDF

	// 压缩包
	{"application/zip", []byte{0x50, 0x4B, 0x03, 0x04}, 0}, // PK.. (ZIP/DOCX/XLSX 等)
	{"application/x-rar", []byte{0x52, 0x61, 0x72, 0x21}, 0}, // Rar!
	{"application/gzip", []byte{0x1F, 0x8B}, 0},
	{"application/x-7z-compressed", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0},

	// 视频
	{"video/mp4", []byte{0x66, 0x74, 0x79, 0x70}, 4}, // ftyp (MP4 容器，offset 4)
	{"video/avi", []byte{0x52, 0x49, 0x46, 0x46}, 0}, // RIFF (AVI)

	// 音频
	{"audio/mpeg", []byte{0xFF, 0xFB}, 0}, // MP3 (MPEG-1 Layer 3)
	{"audio/mpeg", []byte{0x49, 0x44, 0x33}, 0}, // MP3 with ID3v2 tag
}

// dangerousMagicBytes 定义已知危险文件类型的魔术字节（无论 Content-Type 如何都拒绝）。
var dangerousMagicBytes = []struct {
	desc  string
	magic []byte
}{
	// 可执行文件
	{"PE executable (Windows)", []byte{0x4D, 0x5A}}, // MZ (PE/EXE/DLL)
	{"ELF executable (Linux)", []byte{0x7F, 0x45, 0x4C, 0x46}}, // .ELF
	{"Mach-O executable (macOS)", []byte{0xFE, 0xED, 0xFA, 0xCE}}, // Mach-O 32-bit
	{"Mach-O executable (macOS)", []byte{0xFE, 0xED, 0xFA, 0xCF}}, // Mach-O 64-bit

	// 脚本（某些场景可能被解释执行）
	{"Java class file", []byte{0xCA, 0xFE, 0xBA, 0xBE}},
}

// ValidateUpload 验证文件上传请求，检查文件头魔术字节是否与声明的 Content-Type 匹配。
// 返回 nil 表示验证通过，返回 *Result 表示检测到可疑文件。
func (v *FileUploadValidator) ValidateUpload(r *http.Request) *Result {
	// 只检查 multipart/form-data 上传
	if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		return nil
	}
	// 没有请求体可解析：auth_request 子请求是 proxy_pass_request_body off，边缘 WAF
	// 只拿到主请求的 Content-Type 而拿不到 body。此前这里照样 ParseMultipartForm，
	// 必然 "missing form body" → 所有站点的 multipart 上传一律 403 invalid-upload。
	// 上传文件名检测由 site.conf.tmpl 里 location / 的 lua 在能看到 body 的主请求上完成。
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}

	// 解析 multipart 表单（使用配置的最大大小）
	if err := r.ParseMultipartForm(v.maxSize); err != nil {
		// 解析失败可能是格式错误或攻击，拒绝
		return &Result{Action: Block, Rule: "invalid-upload", Message: "invalid multipart form"}
	}

	if r.MultipartForm == nil {
		return nil
	}

	// 检查每个上传的文件
	if r.MultipartForm.File != nil {
		for fieldName, files := range r.MultipartForm.File {
			for _, fileHeader := range files {
				// 检查文件大小
				if fileHeader.Size > v.maxSize {
					return &Result{
						Action:  Block,
						Rule:    "oversized-upload",
						Message: "file too large (field: " + fieldName + ", file: " + fileHeader.Filename + ")",
					}
				}

				// 检查文件名中的危险扩展名和路径穿越
				if res := v.validateFilename(fileHeader.Filename); res != nil {
					res.Message += " (field: " + fieldName + ")"
					return res
				}

				// 检查魔术字节
				if res := v.validateFile(fileHeader); res != nil {
					// 添加字段名到错误信息
					res.Message += " (field: " + fieldName + ", file: " + fileHeader.Filename + ")"
					return res
				}
			}
		}
	}

	return nil
}

// validateFile 验证单个上传文件的魔术字节。
func (v *FileUploadValidator) validateFile(fh *multipart.FileHeader) *Result {
	file, err := fh.Open()
	if err != nil {
		return nil // 打开失败，让后续处理决定
	}
	defer file.Close()

	// 读取文件头（前 512 字节足够检测大部分类型）
	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && err != io.EOF {
		return nil
	}
	header = header[:n]

	// 优先检查是否是危险文件类型（可执行文件、Java class 等）
	for _, danger := range dangerousMagicBytes {
		if bytes.HasPrefix(header, danger.magic) {
			return &Result{
				Action:  Block,
				Rule:    "file-upload-dangerous",
				Message: "dangerous file type detected: " + danger.desc,
			}
		}
	}

	// 检查魔术字节是否与声明的 Content-Type 匹配
	declaredType := fh.Header.Get("Content-Type")
	if declaredType == "" {
		return nil // 未声明类型，不强制校验
	}

	// 尝试从魔术字节推断实际类型
	actualType := v.detectMimeType(header)
	if actualType == "" {
		// 无法识别的文件类型，允许通过（可能是自定义格式）
		return nil
	}

	// 验证声明类型与实际类型是否匹配
	if !v.mimeTypeMatches(declaredType, actualType) {
		return &Result{
			Action:  Block,
			Rule:    "file-upload-mismatch",
			Message: "file type mismatch: declared " + declaredType + ", actual " + actualType,
		}
	}

	return nil
}

// detectMimeType 从文件头魔术字节推断 MIME 类型。
func (v *FileUploadValidator) detectMimeType(header []byte) string {
	for _, sig := range magicBytes {
		if len(header) < sig.offset+len(sig.magic) {
			continue
		}
		if bytes.Equal(header[sig.offset:sig.offset+len(sig.magic)], sig.magic) {
			// 特殊处理 WEBP：需要额外检查 RIFF 后面的 WEBP 标记
			if sig.mime == "image/webp" && len(header) >= 12 {
				if bytes.Equal(header[8:12], []byte("WEBP")) {
					return sig.mime
				}
				continue // RIFF 但不是 WEBP
			}
			return sig.mime
		}
	}
	return ""
}

// mimeTypeMatches 检查声明的 MIME 类型与检测到的类型是否匹配。
// 允许一定的兼容性（如 image/* 匹配任意图片类型）。
func (v *FileUploadValidator) mimeTypeMatches(declared, actual string) bool {
	// 完全匹配
	if declared == actual {
		return true
	}

	// 通配符匹配（如 image/* 匹配 image/jpeg）
	if strings.HasSuffix(declared, "/*") {
		prefix := strings.TrimSuffix(declared, "*")
		if strings.HasPrefix(actual, prefix) {
			return true
		}
	}

	// ZIP 容器兼容性：DOCX/XLSX/PPTX 等都是 ZIP 格式
	if actual == "application/zip" {
		validZipTypes := []string{
			"application/zip",
			"application/vnd.openxmlformats-officedocument", // Office 2007+ (DOCX/XLSX/PPTX)
			"application/vnd.oasis.opendocument", // LibreOffice (ODT/ODS/ODP)
		}
		for _, valid := range validZipTypes {
			if strings.HasPrefix(declared, valid) {
				return true
			}
		}
	}

	return false
}

// validateFilename 检查文件名中的危险扩展名、路径穿越和 null 字节注入。
func (v *FileUploadValidator) validateFilename(filename string) *Result {
	filenameLower := strings.ToLower(filename)

	// 检查路径穿越
	if strings.Contains(filename, "..") || strings.Contains(filename, "\\") {
		return &Result{
			Action:  Block,
			Rule:    "path-traversal",
			Message: "path traversal detected in filename",
		}
	}

	// 检查 null 字节注入
	if strings.Contains(filename, "\x00") {
		return &Result{
			Action:  Block,
			Rule:    "null-byte-injection",
			Message: "null byte detected in filename",
		}
	}

	// 危险的文件扩展名（执行文件、脚本）
	dangerousExtensions := []string{
		".php", ".php3", ".php4", ".php5", ".phtml",
		".asp", ".aspx", ".jsp", ".jspx",
		".exe", ".dll", ".so", ".dylib",
		".sh", ".bash", ".bat", ".cmd", ".ps1",
		".js", ".vbs", ".jar", ".war",
		".py", ".rb", ".pl", ".cgi",
	}

	for _, ext := range dangerousExtensions {
		// 检查最后一个扩展名
		if strings.HasSuffix(filenameLower, ext) {
			return &Result{
				Action:  Block,
				Rule:    "dangerous-extension",
				Message: "dangerous file extension: " + ext,
			}
		}

		// 检查双扩展名（如 shell.php.jpg）
		if strings.Contains(filenameLower, ext+".") {
			return &Result{
				Action:  Block,
				Rule:    "dangerous-extension",
				Message: "dangerous extension in double extension: " + ext,
			}
		}
	}

	return nil
}
