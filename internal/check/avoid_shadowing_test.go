package check_test

import (
	"context"
	"testing"

	"go.szostok.io/codeowners-validator/internal/check"
	"go.szostok.io/codeowners-validator/internal/ptr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAvoidShadowing(t *testing.T) {
	tests := map[string]struct {
		codeownersInput string
		expectedIssues  []check.Issue
	}{
		"Should report info about shadowed entries": {
			codeownersInput: `
					/build/logs/ @doctocat
					/script      @mszostok

					# Shadows
					*            @s1
					/s*/         @s2
					/s*          @s3
					/b*          @s4
					/b*/logs     @s5
                    /dir/        @s6
                    /dir/**      @s7

					# OK
					/b*/other    @o1
					/script/*	 @o2
			`,
			expectedIssues: []check.Issue{
				{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(6),
					Message: `Pattern "*" shadows the following patterns:
            * 2: "/build/logs/"
            * 3: "/script"
Entries should go from least-specific to most-specific.`,
				},
				{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(7),
					Message: `Pattern "/s*/" shadows the following patterns:
            * 3: "/script"
Entries should go from least-specific to most-specific.`,
				},
				{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(8),
					Message: `Pattern "/s*" shadows the following patterns:
            * 3: "/script"
            * 7: "/s*/"
Entries should go from least-specific to most-specific.`,
				},
				{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(9),
					Message: `Pattern "/b*" shadows the following patterns:
            * 2: "/build/logs/"
Entries should go from least-specific to most-specific.`,
				},
				{
					Severity: check.Error,
					LineNo:   ptr.Uint64Ptr(10),
					Message: `Pattern "/b*/logs" shadows the following patterns:
            * 2: "/build/logs/"
Entries should go from least-specific to most-specific.`,
				},
                {
                    Severity: check.Error,
                    LineNo:   ptr.Uint64Ptr(11),
                    Message: `Pattern "/dir/" shadows the following patterns:
            * 8: "/dir/**"
Entries should go from least-specific to most-specific.`,
                },
                {
                    Severity: check.Error,
                    LineNo:   ptr.Uint64Ptr(12),
                    Message: `Pattern "/dir/**" shadows the following patterns:
            * 8: "/dir/"
Entries should go from least-specific to most-specific.`,
                },
			},
		},
		"Should not report any issues with correct CODEOWNERS file": {
			codeownersInput: FixtureValidCODEOWNERS,
			expectedIssues:  nil,
		},
	}

	for tn, tc := range tests {
		t.Run(tn, func(t *testing.T) {
			// given
			sut := check.NewAvoidShadowing()

			// when
			out, err := sut.Check(context.TODO(), LoadInput(tc.codeownersInput))

			// then
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.expectedIssues, out.Issues)
		})
	}
}
