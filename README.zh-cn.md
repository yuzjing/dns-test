# Go DNS Speed Test
[English](README.md)
一个用于测试和评估主流公共 DNS 服务器性能与可靠性的 Go 脚本。

### 核心功能

- **多协议测试**: 支持 UDP, DoT, 和 DoH。
- **真实结果**: 绕过本地 DNS 缓存与劫持。
- **场景化**: 分别测试国内与国外网站。
- **双重指标**: 同时评估响应速度与成功率。

### 如何运行

```bash
# (首次运行前，请确保已通过 go mod tidy 下载依赖)
go run main.go
```
