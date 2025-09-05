# Go DNS Speed Test

[简体中文](README.zh-cn.md)

A Go script for testing and evaluating the performance and reliability of major public DNS servers.

### Core Features

- **Multi-Protocol Testing**: Supports UDP, DoT, and DoH.
- **Real Results**: Bypasses local DNS cache and hijacking.
- **Scenario-based**: Tests domestic and international websites separately.
- **Dual Metrics**: Evaluates both response speed and success rate.

### How to Run

```bash
# (Before the first run, please make sure to download dependencies via go mod tidy)
go run main.go
```
