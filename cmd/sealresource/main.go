// sealresource 是构建期工具：读取明文文件，使用 internal/secure 的内置密钥加密，
// 输出 .enc 文件供 go:embed 使用。产品二进制里不含它。
package main

import (
	"flag"
	"log"
	"os"

	"cdn/internal/secure"
)

func main() {
	in := flag.String("in", "", "input file path")
	out := flag.String("out", "", "output file path")
	decrypt := flag.Bool("d", false, "decrypt .enc back to plaintext instead of sealing")
	flag.Parse()

	if *in == "" || *out == "" {
		log.Fatal("usage: sealresource [-d] -in <file> -out <file>")
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		log.Fatalf("read input: %v", err)
	}

	if *decrypt {
		plain, err := secure.Decrypt(data)
		if err != nil {
			log.Fatalf("decrypt: %v", err)
		}
		if err := os.WriteFile(*out, plain, 0644); err != nil {
			log.Fatalf("write output: %v", err)
		}
		log.Printf("unsealed %s -> %s (%d bytes -> %d bytes)", *in, *out, len(data), len(plain))
		return
	}

	enc, err := secure.Encrypt(data)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	if err := os.WriteFile(*out, enc, 0644); err != nil {
		log.Fatalf("write output: %v", err)
	}

	log.Printf("sealed %s -> %s (%d bytes -> %d bytes)", *in, *out, len(data), len(enc))
}
