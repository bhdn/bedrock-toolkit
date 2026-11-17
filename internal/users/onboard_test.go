package users

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	itypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeLoginProfiles struct {
	loginErr, policyErr, createErr error
	minimum                        int32
	created                        *iam.CreateLoginProfileInput
}

func (f *fakeLoginProfiles) GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	return &iam.GetLoginProfileOutput{}, f.loginErr
}
func (f *fakeLoginProfiles) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: &itypes.PasswordPolicy{MinimumPasswordLength: aws.Int32(f.minimum)}}, f.policyErr
}
func (f *fakeLoginProfiles) CreateLoginProfile(_ context.Context, in *iam.CreateLoginProfileInput, _ ...func(*iam.Options)) (*iam.CreateLoginProfileOutput, error) {
	f.created = in
	return &iam.CreateLoginProfileOutput{}, f.createErr
}
func TestCreateConsolePassword(t *testing.T) {
	absent := &itypes.NoSuchEntityException{}
	denied := errors.New("access denied")
	for _, tc := range []struct {
		name                           string
		loginErr, policyErr, createErr error
		dry                            bool
		wantErr                        bool
		wantCreate                     bool
	}{
		{"new", absent, nil, nil, false, false, true},
		{"default policy", absent, absent, nil, false, false, true},
		{"existing", nil, nil, nil, false, true, false},
		{"unreadable login", denied, nil, nil, false, true, false},
		{"unreadable policy", absent, denied, nil, false, true, false},
		{"dry run", absent, nil, nil, true, false, false},
		{"create race", absent, nil, &itypes.EntityAlreadyExistsException{}, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLoginProfiles{loginErr: tc.loginErr, policyErr: tc.policyErr, createErr: tc.createErr, minimum: 64}
			password, err := createConsolePassword(context.Background(), f, "alice", tc.dry)
			if (err != nil) != tc.wantErr || (f.created != nil) != tc.wantCreate {
				t.Fatalf("err=%v created=%v", err, f.created != nil)
			}
			if tc.wantErr || tc.dry {
				if password != "" {
					t.Fatal("returned a password without success")
				}
				return
			}
			wantLength := 64
			if tc.policyErr != nil {
				wantLength = 32
			}
			if len(password) != wantLength || aws.ToString(f.created.UserName) != "alice" || !f.created.PasswordResetRequired || aws.ToString(f.created.Password) != password {
				t.Fatal("wrong login profile")
			}
			for _, class := range []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%^&*"} {
				if !strings.ContainsAny(password, class) {
					t.Fatal("missing character class")
				}
			}
		})
	}
}
