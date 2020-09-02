package api

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projecteru2/barrel/utils"
)

const (
	// FixedIPLabel .
	FixedIPLabel = "fixed-ip"
)

func isFixedIPEnable(label utils.Any) bool {
	if label.Null() {
		return true
	}
	if str, ok := label.StringValue(); ok {
		return isFixedIPEnableByStringValue(str)
	}
	if i, ok := label.IntValue(); ok {
		return i != 0
	}
	if b, ok := label.BoolValue(); ok {
		return b
	}
	// otherwise regard as true
	return true
}

func isFixedIPEnableByStringValue(value string) bool {
	return value != "0" && strings.ToLower(value) != "false"
}

func ensureObjectMember(parent utils.Object, key string) (childObject utils.Object, err error) {
	if child, ok := parent.Get(key); !ok || child.Null() {
		childObject = utils.NewObjectNode()
		parent.Set(key, childObject.Any())
	} else if childObject, ok = child.ObjectValue(); !ok {
		err = errors.Errorf(`parse object.["%s"] error, value=%s`, key, child.String())
		return
	}
	return
}

func getStringMember(parent utils.Object, key string) (result string, err error) {
	if child, ok := parent.Get(key); !ok || child.Null() {
		return
	} else if result, ok = child.StringValue(); !ok {
		err = errors.Errorf(`parse object.["%s"] as string error, value=%s`, key, child.String())
		return
	}
	return
}