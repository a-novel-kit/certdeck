// Code generated by mockery v2.50.0. DO NOT EDIT.

package certdeckmocks

import (
	mock "github.com/stretchr/testify/mock"

	certdeck "github.com/a-novel-kit/certdeck"
)

// MockCollectionUpdater is an autogenerated mock type for the CertsProvider type
type MockCollectionUpdater struct {
	mock.Mock
}

type MockCollectionUpdater_Expecter struct {
	mock *mock.Mock
}

func (_m *MockCollectionUpdater) EXPECT() *MockCollectionUpdater_Expecter {
	return &MockCollectionUpdater_Expecter{mock: &_m.Mock}
}

// ID provides a mock function with no fields
func (_m *MockCollectionUpdater) ID() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ID")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockCollectionUpdater_ID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ID'
type MockCollectionUpdater_ID_Call struct {
	*mock.Call
}

// ID is a helper method to define mock.On call
func (_e *MockCollectionUpdater_Expecter) ID() *MockCollectionUpdater_ID_Call {
	return &MockCollectionUpdater_ID_Call{Call: _e.mock.On("ID")}
}

func (_c *MockCollectionUpdater_ID_Call) Run(run func()) *MockCollectionUpdater_ID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockCollectionUpdater_ID_Call) Return(_a0 string) *MockCollectionUpdater_ID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockCollectionUpdater_ID_Call) RunAndReturn(run func() string) *MockCollectionUpdater_ID_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with no fields
func (_m *MockCollectionUpdater) Retrieve() (certdeck.CollectionRow, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Retrieve")
	}

	var r0 certdeck.CollectionRow
	var r1 error
	if rf, ok := ret.Get(0).(func() (certdeck.CollectionRow, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() certdeck.CollectionRow); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(certdeck.CollectionRow)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockCollectionUpdater_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Retrieve'
type MockCollectionUpdater_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
func (_e *MockCollectionUpdater_Expecter) Update() *MockCollectionUpdater_Update_Call {
	return &MockCollectionUpdater_Update_Call{Call: _e.mock.On("Retrieve")}
}

func (_c *MockCollectionUpdater_Update_Call) Run(run func()) *MockCollectionUpdater_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockCollectionUpdater_Update_Call) Return(_a0 certdeck.CollectionRow, _a1 error) *MockCollectionUpdater_Update_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockCollectionUpdater_Update_Call) RunAndReturn(run func() (certdeck.CollectionRow, error)) *MockCollectionUpdater_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockCollectionUpdater creates a new instance of MockCollectionUpdater. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockCollectionUpdater(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockCollectionUpdater {
	mock := &MockCollectionUpdater{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
