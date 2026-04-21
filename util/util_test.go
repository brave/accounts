package util_test

import (
	"testing"

	"github.com/brave/accounts/util"
	"github.com/stretchr/testify/suite"
)

type UtilTest struct {
	suite.Suite
}

func (suite *UtilTest) TestSimplifyEmail() {
	result := util.SimplifyEmail("test@gmail.com")
	suite.Require().NotNil(result)
	suite.Equal("test@gmail.com", *result)

	result = util.SimplifyEmail("t.e.s.t@gmail.com")
	suite.Require().NotNil(result)
	suite.Equal("test@gmail.com", *result)

	result = util.SimplifyEmail("test+spam@gmail.com")
	suite.Require().NotNil(result)
	suite.Equal("test@gmail.com", *result)

	result = util.SimplifyEmail("t.e.s.t+spam@gmail.com")
	suite.Require().NotNil(result)
	suite.Equal("test@gmail.com", *result)

	result = util.SimplifyEmail("test@example.com")
	suite.Nil(result)

	result = util.SimplifyEmail("test@googlemail.com")
	suite.Require().NotNil(result)
	suite.Equal("test@gmail.com", *result)
}

func (suite *UtilTest) TestCanonicalizeEmail() {
	result := util.CanonicalizeEmail("test@example.com")
	suite.Require().NotNil(result)
	suite.Equal("test@example.com", result)

	result = util.CanonicalizeEmail("test@ExAmPlE.CoM")
	suite.Require().NotNil(result)
	suite.Equal("test@example.com", result)

	result = util.CanonicalizeEmail("TestTest@ExAmPlE.CoM")
	suite.Require().NotNil(result)
	suite.Equal("TestTest@example.com", result)

	result = util.CanonicalizeEmail("TeSt@GmAiL.CoM")
	suite.Require().NotNil(result)
	suite.Equal("test@gmail.com", result)

	result = util.CanonicalizeEmail("\"test@Foo\"@gmail.com")
	suite.Require().NotNil(result)
	suite.Equal("\"test@foo\"@gmail.com", result)

	result = util.CanonicalizeEmail("\"test@Foo\"@Example.com")
	suite.Require().NotNil(result)
	suite.Equal("\"test@Foo\"@example.com", result)
}

func (suite *UtilTest) TestVerificationCodeEquals() {
	// Uppercase
	suite.True(util.VerificationCodeEquals("abcdef", "ABCDEF"))
	// Whitespace removal
	suite.True(util.VerificationCodeEquals("ABC DEF", "ABCDEF"))
	suite.True(util.VerificationCodeEquals("AB\tCD\nEF", "ABCDEF"))
	// Hyphen removal
	suite.True(util.VerificationCodeEquals("ABC-DEF", "ABCDEF"))
	// 1 -> I
	suite.True(util.VerificationCodeEquals("1ABCDE", "IABCDE"))
	// 8 -> B
	suite.True(util.VerificationCodeEquals("8ABCDE", "BABCDE"))
	// 0 -> O
	suite.True(util.VerificationCodeEquals("0ABCDE", "OABCDE"))
	// Combined
	suite.True(util.VerificationCodeEquals("1 0-8-8cd", "IOBBCD"))
	// Mismatch
	suite.False(util.VerificationCodeEquals("ABCDEF", "XYZXYZ"))
}

func TestUtil(t *testing.T) {
	suite.Run(t, new(UtilTest))
}
