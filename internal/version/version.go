// Package version 只放一件事：让面板和边缘能说出"我是哪一次构建产出来的"。
package version

// Build 由构建脚本用 -ldflags "-X cdn/internal/version.Build=cdn-YYYYMMDD-HHMM" 注入。
//
// 为什么是构建号而不是 git tag / debug.ReadBuildInfo：本工作区不是 git 仓库，没有
// commit 也没有 tag 可取；ReadBuildInfo 在 go build 的普通产物里只有模块版本 "(devel)"，
// 区分不出同一天里出的两个包。而这里真正要回答的问题是"节点上跑的那份边缘，和面板
// 准备下发的那份是不是同一次构建"——一个时间戳就够，还顺带能看出差多久。
//
// 默认值 "dev" 表示本地 go build、没走 build.sh。面板侧把它当成"版本未知"而不是
// "版本落后"，避免把开发机构建判成故障节点。
var Build = "dev"
