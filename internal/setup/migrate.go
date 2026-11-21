package setup

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// errTableExists 是 RunMigration 在建表语句命中 MySQL 1050（表已存在）时返回的
// 标记错误，调用方（安装向导）据此判断"这个库已经装过一次了"，而不是把原始 SQL
// 报错糊给用户看。用 errors.Is 判断，不用字符串匹配，避免消息文案变化后失效。
var errTableExists = errors.New("table already exists")

// IsTableExistsError 判断 RunMigration 返回的错误是否是"库已装过"（MySQL 1050）。
func IsTableExistsError(err error) bool {
	return errors.Is(err, errTableExists)
}

var delimiterDirective = regexp.MustCompile(`(?i)^DELIMITER\s+(\S+)\s*$`)

// SplitStatements 按 DELIMITER 指令切分 SQL 文本为一条条可执行语句。
// 迁移文件里的每条语句都在某一行以当前分隔符收尾（";" 或存储过程/触发器块用的 "$$"），
// 所以只需逐行累积，一旦累积内容以分隔符结尾就切出一条语句。
func SplitStatements(sqlText string) ([]string, error) {
	delimiter := ";"
	var stmts []string
	var buf strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(sqlText))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		if m := delimiterDirective.FindStringSubmatch(trimmed); m != nil {
			delimiter = m[1]
			continue
		}

		buf.WriteString(line)
		buf.WriteByte('\n')

		content := strings.TrimRight(buf.String(), " \t\r\n")
		if strings.HasSuffix(content, delimiter) {
			stmt := strings.TrimSpace(content[:len(content)-len(delimiter)])
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			buf.Reset()
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(buf.String()) != "" {
		return nil, fmt.Errorf("SQL 文件末尾存在未以分隔符 %q 结尾的语句", delimiter)
	}
	return stmts, nil
}

// RunMigration 依次执行迁移 SQL 的每条语句。DDL 在 MySQL 里不在事务内，
// 中途失败需要人工检查库里已创建到哪一步，这里不做额外的幂等兜底。
func RunMigration(db *sql.DB, sqlText string) error {
	stmts, err := SplitStatements(sqlText)
	if err != nil {
		return err
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			var mysqlErr *mysql.MySQLError
			if errors.As(err, &mysqlErr) && mysqlErr.Number == 1050 { // ER_TABLE_EXISTS_ERROR
				return fmt.Errorf("%w: %v", errTableExists, err)
			}
			return fmt.Errorf("执行语句失败: %w\n语句:\n%s", err, stmt)
		}
	}
	return nil
}
