// Package metadata provides strict shared primitives for provider metadata readers.
// Package metadata 为供应商元数据读取器提供严格的共享基础类型。
package metadata

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// decimalPattern matches the canonical catalog decimal grammar without exponent notation.
// decimalPattern 匹配不含指数表示的规范目录十进制语法。
var decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// Decimal preserves one provider number as its exact base-10 representation.
// Decimal 以精确十进制表示保留一个供应商数值。
type Decimal struct {
	// value is the validated non-negative decimal text.
	// value 是经过校验的非负十进制文本。
	value string
	// set distinguishes an explicit zero from an omitted field.
	// set 区分显式零值与省略字段。
	set bool
}

// UnmarshalJSON accepts only finite non-negative JSON numbers or numeric strings.
// UnmarshalJSON 仅接受有限非负 JSON 数值或数值字符串。
func (d *Decimal) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errors.New("metadata decimal target is nil")
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) || len(trimmed) == 0 {
		*d = Decimal{}
		return nil
	}
	var raw string
	if trimmed[0] == '"' {
		if errDecode := json.Unmarshal(trimmed, &raw); errDecode != nil {
			return errors.New("metadata decimal string is invalid")
		}
	} else {
		raw = string(trimmed)
	}
	normalized := strings.TrimSpace(raw)
	number, errNumber := strconv.ParseFloat(normalized, 64)
	if normalized == "" || !decimalPattern.MatchString(normalized) || errNumber != nil || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 {
		return errors.New("metadata decimal must be finite and non-negative")
	}
	d.value = normalized
	d.set = true
	return nil
}

// Set reports whether the provider returned this field.
// Set 报告供应商是否返回了该字段。
func (d Decimal) Set() bool {
	return d.set
}

// String returns the exact validated decimal text.
// String 返回经过校验的精确十进制文本。
func (d Decimal) String() string {
	return d.value
}

// Float64 returns the finite parsed value for ratio calculations.
// Float64 返回用于比例计算的有限解析值。
func (d Decimal) Float64() float64 {
	value, _ := strconv.ParseFloat(d.value, 64)
	return value
}
