package admincli

import (
	"fmt"

	"github.com/SUSE/bedrock-toolkit/internal/cli"
	"github.com/SUSE/bedrock-toolkit/internal/users"
	"github.com/spf13/cobra"
)

func (a *App) onboardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "onboard <email>",
		Short: "Issue an IAM user's initial console password for self-service access keys",
		Long: `onboard creates a console login for an IAM user already configured by apply.
It prints a temporary password for the admin to hand over securely. The user must change it
on first sign-in, then creates their own access key on the Security credentials page.
Existing console passwords are never replaced. Output contains a secret: do not put it in logs.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := a.load()
			if err != nil {
				return err
			}
			u, ok := cfg.FindUser(args[0])
			if !ok {
				return fmt.Errorf("%s is not in the config file", args[0])
			}
			if u.IAMUser == "" {
				return fmt.Errorf("%s has no iam_user in the file", u.Email)
			}
			c, err := a.clients(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			env := a.usersEnv(cmd.Context(), cfg, c)
			password, err := env.Onboard(cmd.Context(), u, a.DryRun)
			if err != nil {
				return err
			}
			url := "https://" + c.Account + ".signin.aws.amazon.com/console"
			setup := users.SetupCommand(cfg, c.Account, env.ProfileRegion, u)
			if a.JSON {
				return cli.WriteJSON(a.Out, struct {
					Email             string `json:"email"`
					Username          string `json:"username"`
					SignInURL         string `json:"sign_in_url"`
					TemporaryPassword string `json:"temporary_password,omitempty"`
					SetupCommand      string `json:"setup_command"`
					DryRun            bool   `json:"dry_run"`
				}{u.Email, u.IAMUser, url, password, setup, a.DryRun})
			}
			if a.DryRun {
				_, err = fmt.Fprintf(a.Out, "Would create a console login for %s with a password change required on first sign-in.\n", u.IAMUser)
			} else {
				_, err = fmt.Fprintf(a.Out, "Hand these details to %s securely. The temporary password is shown only now.\nSign-in URL: %s\nUsername: %s\nTemporary password: %s\n\nSign in, change your password, then open Security credentials and create an access key.\nSkip the optional access key description. Run these commands to store the key and set up Bedrock:\n%s\n", u.Email, url, u.IAMUser, password, setup)
			}
			return err
		},
	}
}
