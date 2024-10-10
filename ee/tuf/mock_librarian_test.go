// Code generated by mockery v2.45.0. DO NOT EDIT.

package tuf

import (
	mock "github.com/stretchr/testify/mock"
	metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// Mocklibrarian is an autogenerated mock type for the librarian type
type Mocklibrarian struct {
	mock.Mock
}

// AddToLibrary provides a mock function with given fields: binary, currentVersion, targetFilename, targetMetadata
func (_m *Mocklibrarian) AddToLibrary(binary autoupdatableBinary, currentVersion string, targetFilename string, targetMetadata *metadata.TargetFiles) error {
	ret := _m.Called(binary, currentVersion, targetFilename, targetMetadata)

	if len(ret) == 0 {
		panic("no return value specified for AddToLibrary")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(autoupdatableBinary, string, string, *metadata.TargetFiles) error); ok {
		r0 = rf(binary, currentVersion, targetFilename, targetMetadata)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Available provides a mock function with given fields: binary, targetFilename
func (_m *Mocklibrarian) Available(binary autoupdatableBinary, targetFilename string) bool {
	ret := _m.Called(binary, targetFilename)

	if len(ret) == 0 {
		panic("no return value specified for Available")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(autoupdatableBinary, string) bool); ok {
		r0 = rf(binary, targetFilename)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// TidyLibrary provides a mock function with given fields: binary, currentVersion
func (_m *Mocklibrarian) TidyLibrary(binary autoupdatableBinary, currentVersion string) {
	_m.Called(binary, currentVersion)
}

// NewMocklibrarian creates a new instance of Mocklibrarian. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMocklibrarian(t interface {
	mock.TestingT
	Cleanup(func())
}) *Mocklibrarian {
	mock := &Mocklibrarian{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
