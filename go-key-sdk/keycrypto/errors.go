package keycrypto

import (
	"errors"
	"fmt"
)

// Code 是三個語言必須一致的錯誤碼。呼叫端以 CodeOf 取得，不解析訊息字串。
type Code string

const (
	ErrFormat         Code = "ERR_FORMAT"          // 前綴／長度／版本位元組／base64url 非法
	ErrUnknownKID     Code = "ERR_UNKNOWN_KID"     // kid 未登記、已退役或與金鑰不符
	ErrKey            Code = "ERR_KEY"             // 公鑰無效或不在曲線上
	ErrAuth           Code = "ERR_AUTH"            // GCM 認證失敗
	ErrStale          Code = "ERR_STALE"           // 快照超過 300 秒
	ErrUnavailable    Code = "ERR_UNAVAILABLE"     // 中央逾時或 5xx
	ErrUnauthorized   Code = "ERR_UNAUTHORIZED"    // 403：未登記／停用／IP 不符
	ErrPolicyDisabled Code = "ERR_POLICY_DISABLED" // 中央明確回傳不加密
)

// Error 帶固定錯誤碼，訊息僅供日誌使用。
type Error struct {
	Code Code
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Msg, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Msg)
}

func (e *Error) Unwrap() error { return e.Err }

func newErr(c Code, format string, a ...any) error {
	return &Error{Code: c, Msg: fmt.Sprintf(format, a...)}
}

func wrapErr(c Code, err error, format string, a ...any) error {
	return &Error{Code: c, Msg: fmt.Sprintf(format, a...), Err: err}
}

// CodeOf 取出錯誤碼；非本套件產生的錯誤回傳空字串。
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
