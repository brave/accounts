package datastore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type VerificationsTestSuite struct {
	suite.Suite
}

func (suite *VerificationsTestSuite) TestGenerateVerificationCode() {
	cases := []string{
		"F",                // length 1, F branch
		"D",                // length 1, D branch
		"FFDFFD",           // length 6, both branches (production pattern)
		"FFFFFFFFFFFFFFFF", // length 16
	}

	const iterations = 50

	for _, pattern := range cases {
		suite.Run(pattern, func() {
			for i := 0; i < iterations; i++ {
				code, err := generateVerificationCode(pattern)
				suite.Require().NoError(err)
				suite.Require().Len(code, len(pattern))
				for pos, c := range []byte(code) {
					var allowed string
					switch pattern[pos] {
					case 'F':
						allowed = codeAlphabetFull
					case 'D':
						allowed = codeAlphabetDigit
					}
					suite.True(strings.ContainsRune(allowed, rune(c)),
						"code %q pos %d: char %q not in alphabet %q", code, pos, c, allowed)
				}
			}
		})
	}
}

func (suite *VerificationsTestSuite) TestGenerateVerificationCodeInvalidPattern() {
	cases := []string{"", "FFXFFD"}
	for _, p := range cases {
		suite.Run(p, func() {
			code, err := generateVerificationCode(p)
			suite.Require().Error(err, "expected error for pattern %q, got code=%q", p, code)
		})
	}
}

func (suite *VerificationsTestSuite) TestGenerateVerificationCodeDistribution() {
	// Smoke test for non-determinism: a long enough run should not always
	// return the same code. Catches obvious seeding/PRNG bugs.
	const pattern = "FFDFFD"
	const iterations = 50
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		code, err := generateVerificationCode(pattern)
		suite.Require().NoError(err)
		seen[code] = struct{}{}
	}
	suite.GreaterOrEqual(len(seen), iterations/2,
		"expected mostly distinct codes over %d runs, got %d unique", iterations, len(seen))
}

func TestVerificationsTestSuite(t *testing.T) {
	suite.Run(t, new(VerificationsTestSuite))
}
