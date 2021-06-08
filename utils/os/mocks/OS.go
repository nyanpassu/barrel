// Code generated by mockery v2.8.0. DO NOT EDIT.

package mocks

import (
	fs "io/fs"

	mock "github.com/stretchr/testify/mock"
)

// OS is an autogenerated mock type for the OS type
type OS struct {
	mock.Mock
}

// Stat provides a mock function with given fields: name
func (_m *OS) Stat(name string) (fs.FileInfo, error) {
	ret := _m.Called(name)

	var r0 fs.FileInfo
	if rf, ok := ret.Get(0).(func(string) fs.FileInfo); ok {
		r0 = rf(name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(fs.FileInfo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}