// Package apierr 是 console-server 的错误响应：{code, msg, reason?, details?}，HTTP 状态取 errors.json 的 http 字段。
// console-server 只定义自己产生的码；im-server 返回的 admin 通道错误码原样透传（ERRORS.md 第 2 节）。
package apierr

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// console 通道的错误码。一致性由 TestConsoleCodesMatchErrorsJSON 保证。
const (
	BadRequest         = 4000
	InvalidID          = 4004
	InvalidConvID      = 4007
	AuthRequired       = 4014
	CredentialsInvalid = 4015
	SetupRequired      = 4016
	Forbidden          = 4030
	CSRFInvalid        = 4037
	StepUpRequired     = 4038
	MsgReadGrantNeeded = 4039
	NotFound           = 4040
	MessageNotFound    = 4044
	AccountExists      = 4092
	AccountConflict    = 4093
	MemberLimit        = 4130
	BatchLimit         = 4131
	RateLimited        = 4290
	LoginLocked        = 4291
	QuotaExceeded      = 4292
	Internal           = 5000
	Unavailable        = 5030
	AuditUnavailable   = 5031
	ResultUnknown      = 5040
)

type info struct {
	name string
	http int
}

var codes = map[int]info{
	BadRequest:         {"BAD_REQUEST", 400},
	InvalidID:          {"INVALID_ID", 400},
	InvalidConvID:      {"INVALID_CONV_ID", 400},
	AuthRequired:       {"CONSOLE_AUTH_REQUIRED", 401},
	CredentialsInvalid: {"CONSOLE_CREDENTIALS_INVALID", 401},
	SetupRequired:      {"CONSOLE_SETUP_REQUIRED", 401},
	Forbidden:          {"FORBIDDEN", 403},
	CSRFInvalid:        {"CSRF_INVALID", 403},
	StepUpRequired:     {"STEP_UP_REQUIRED", 403},
	MsgReadGrantNeeded: {"MSG_READ_GRANT_REQUIRED", 403},
	NotFound:           {"NOT_FOUND", 404},
	MessageNotFound:    {"MESSAGE_NOT_FOUND", 404},
	AccountExists:      {"CONSOLE_ACCOUNT_EXISTS", 409},
	AccountConflict:    {"CONSOLE_ACCOUNT_STATE_CONFLICT", 409},
	MemberLimit:        {"GROUP_MEMBER_LIMIT_EXCEEDED", 400},
	BatchLimit:         {"BATCH_LIMIT_EXCEEDED", 400},
	RateLimited:        {"RATE_LIMITED", 429},
	LoginLocked:        {"CONSOLE_LOGIN_LOCKED", 429},
	QuotaExceeded:      {"QUOTA_EXCEEDED", 429},
	Internal:           {"INTERNAL", 500},
	Unavailable:        {"SERVICE_UNAVAILABLE", 503},
	AuditUnavailable:   {"AUDIT_UNAVAILABLE", 503},
	ResultUnknown:      {"UPSTREAM_RESULT_UNKNOWN", 504},
}

// Error 是错误响应体。
type Error struct {
	Code    int            `json:"code"`
	Msg     string         `json:"msg"`
	Reason  string         `json:"reason,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Msg) }

// New 创建错误。
func New(code int, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// HTTPStatus 取错误码的 HTTP 状态。透传的 admin 码不在表里时按前三位。
func HTTPStatus(code int) int {
	if i, ok := codes[code]; ok {
		return i.http
	}
	return code / 10
}

// Write 写错误响应。
func Write(w http.ResponseWriter, e *Error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(HTTPStatus(e.Code))
	_ = json.NewEncoder(w).Encode(e)
}
