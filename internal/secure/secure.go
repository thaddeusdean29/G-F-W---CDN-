// Package secure 提供核心资源（WAF 规则、Tengine 模板等）的编译期加密/运行期解密能力，
// 避免这些数据以明文字符串形式出现在编译产物中。
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// resourceKey 是内置于二进制中的 AES-256 密钥。
// 该常量本身会被 garble -literals 在编译期进一步混淆存储形式。
var resourceKey = [32]byte{
	0xa4, 0xf0, 0xdd, 0xa9, 0x70, 0x2f, 0x2d, 0xf9,
	0x8e, 0xc8, 0xc7, 0xd5, 0x2e, 0x1f, 0xe5, 0xe7,
	0xfe, 0x9d, 0xbc, 0xc2, 0x8a, 0xdc, 0xcf, 0x13,
	0x13, 0x17, 0x64, 0xe4, 0xe3, 0x32, 0x38, 0x10,
}

// Encrypt 使用内置密钥对 plaintext 加密，输出 nonce+密文+tag 拼接的字节流。
func Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(resourceKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt 使用内置密钥解密 Encrypt 产生的数据。
func Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(resourceKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("secure: ciphertext too short")
	}
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}

// DeriveKey 基于内置密钥为特定用途派生一个子密钥，避免不同用途复用同一密钥。
// 所有边缘节点二进制内置同一份 resourceKey，因此同一 purpose 在所有节点上派生出相同的子密钥，
// 无需额外的主控→边缘同步即可让签发方和校验方使用一致的密钥。
func DeriveKey(purpose string) []byte {
	mac := hmac.New(sha256.New, resourceKey[:])
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

// MustDecrypt 与 Decrypt 相同，但在解密失败时直接 panic。
// 用于程序初始化阶段加载内置加密资源——这些资源理应始终能成功解密，
// 失败意味着二进制被篡改或构建流程出错，此时继续运行没有意义。
func MustDecrypt(ciphertext []byte) []byte {
	data, err := Decrypt(ciphertext)
	if err != nil {
		panic("secure: failed to decrypt embedded resource: " + err.Error())
	}
	return data
}
