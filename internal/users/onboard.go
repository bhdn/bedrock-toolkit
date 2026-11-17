package users

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/SUSE/bedrock-toolkit/internal/config"
)

// Onboard creates a console password only after apply has enrolled the configured IAM user.
// It never replaces a login profile or creates access keys.
func (e *Env) Onboard(ctx context.Context, u config.Resolved, dryRun bool) (string, error) {
	if u.IAMUser == "" {
		return "", fmt.Errorf("%s has no iam_user in the file", u.Email)
	}
	o, err := e.observeIAMUser(ctx, u.IAMUser)
	if err != nil {
		return "", err
	}
	if !o.Exists || o.Name != u.IAMUser || o.ID != e.Cfg.ID || o.Owner != u.Email || !o.Attached {
		return "", fmt.Errorf("IAM user %s is not configured for %s; run bedrock-admin apply first", u.IAMUser, u.Email)
	}
	return createConsolePassword(ctx, e.C.IAM, u.IAMUser, dryRun)
}

type loginProfiles interface {
	GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	CreateLoginProfile(context.Context, *iam.CreateLoginProfileInput, ...func(*iam.Options)) (*iam.CreateLoginProfileOutput, error)
}

func createConsolePassword(ctx context.Context, c loginProfiles, name string, dryRun bool) (string, error) {
	_, err := c.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: aws.String(name)})
	if err == nil {
		return "", fmt.Errorf("IAM user %s already has a console password; left unchanged", name)
	}
	if !isNoSuchEntity(err) {
		return "", fmt.Errorf("reading console login for %s: %w", name, err)
	}
	// Meet every character class and the account's minimum length, including policies over 32.
	length := 32
	p, err := c.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil && !isNoSuchEntity(err) {
		return "", fmt.Errorf("reading account password policy: %w", err)
	}
	if err == nil && p.PasswordPolicy != nil && int(aws.ToInt32(p.PasswordPolicy.MinimumPasswordLength)) > length {
		length = int(aws.ToInt32(p.PasswordPolicy.MinimumPasswordLength))
	}
	if dryRun {
		return "", nil
	}
	password := randomConsolePassword(length)
	_, err = c.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{
		UserName: aws.String(name), Password: aws.String(password), PasswordResetRequired: true,
	})
	if err != nil {
		return "", fmt.Errorf("creating console login for %s: %w", name, err)
	}
	return password, nil
}

func randomConsolePassword(length int) string {
	// rand.Text supplies 128 bits of entropy; the prefix satisfies IAM character-class rules.
	password := "aA1!" + rand.Text()
	for len(password) < length {
		password += rand.Text()
	}
	return password[:length]
}
