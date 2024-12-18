// Code generated by mockery v2.50.0. DO NOT EDIT.

package certdeckmocks

import (
	context "context"

	certdeck "github.com/a-novel-kit/certdeck"

	crypto "crypto"

	mock "github.com/stretchr/testify/mock"

	x509 "crypto/x509"
)

// MockSigner is an autogenerated mock type for the Signer type
type MockSigner struct {
	mock.Mock
}

type MockSigner_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSigner) EXPECT() *MockSigner_Expecter {
	return &MockSigner_Expecter{mock: &_m.Mock}
}

// Rotate provides a mock function with given fields: issuers, issuerKey
func (_m *MockSigner) Rotate(issuers []*x509.Certificate, issuerKey crypto.Signer) {
	_m.Called(issuers, issuerKey)
}

// MockSigner_Rotate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Rotate'
type MockSigner_Rotate_Call struct {
	*mock.Call
}

// Rotate is a helper method to define mock.On call
//   - issuers []*x509.Certificate
//   - issuerKey crypto.Signer
func (_e *MockSigner_Expecter) Rotate(issuers interface{}, issuerKey interface{}) *MockSigner_Rotate_Call {
	return &MockSigner_Rotate_Call{Call: _e.mock.On("Rotate", issuers, issuerKey)}
}

func (_c *MockSigner_Rotate_Call) Run(run func(issuers []*x509.Certificate, issuerKey crypto.Signer)) *MockSigner_Rotate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]*x509.Certificate), args[1].(crypto.Signer))
	})
	return _c
}

func (_c *MockSigner_Rotate_Call) Return() *MockSigner_Rotate_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockSigner_Rotate_Call) RunAndReturn(run func([]*x509.Certificate, crypto.Signer)) *MockSigner_Rotate_Call {
	_c.Run(run)
	return _c
}

// Sign provides a mock function with given fields: ctx, key, keyID, template
func (_m *MockSigner) Sign(ctx context.Context, key interface{}, keyID []byte, template *certdeck.Template) (*x509.Certificate, error) {
	ret := _m.Called(ctx, key, keyID, template)

	if len(ret) == 0 {
		panic("no return value specified for Sign")
	}

	var r0 *x509.Certificate
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, interface{}, []byte, *certdeck.Template) (*x509.Certificate, error)); ok {
		return rf(ctx, key, keyID, template)
	}
	if rf, ok := ret.Get(0).(func(context.Context, interface{}, []byte, *certdeck.Template) *x509.Certificate); ok {
		r0 = rf(ctx, key, keyID, template)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*x509.Certificate)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, interface{}, []byte, *certdeck.Template) error); ok {
		r1 = rf(ctx, key, keyID, template)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSigner_Sign_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Sign'
type MockSigner_Sign_Call struct {
	*mock.Call
}

// Sign is a helper method to define mock.On call
//   - ctx context.Context
//   - key interface{}
//   - keyID []byte
//   - template *certdeck.Template
func (_e *MockSigner_Expecter) Sign(ctx interface{}, key interface{}, keyID interface{}, template interface{}) *MockSigner_Sign_Call {
	return &MockSigner_Sign_Call{Call: _e.mock.On("Sign", ctx, key, keyID, template)}
}

func (_c *MockSigner_Sign_Call) Run(run func(ctx context.Context, key interface{}, keyID []byte, template *certdeck.Template)) *MockSigner_Sign_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(interface{}), args[2].([]byte), args[3].(*certdeck.Template))
	})
	return _c
}

func (_c *MockSigner_Sign_Call) Return(_a0 *x509.Certificate, _a1 error) *MockSigner_Sign_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSigner_Sign_Call) RunAndReturn(run func(context.Context, interface{}, []byte, *certdeck.Template) (*x509.Certificate, error)) *MockSigner_Sign_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSigner creates a new instance of MockSigner. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSigner(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSigner {
	mock := &MockSigner{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
