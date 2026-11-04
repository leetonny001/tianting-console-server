// Package api 放接口清单。
package api

import _ "embed"

// OpsRoutes 是 ops-routes.yaml 的内容。
//
//go:embed ops-routes.yaml
var OpsRoutes []byte
