package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"NanoKVM-Server/utils"
)

const AccountFile = "/etc/kvm/accounts.json"
const LegacyAccountFile = "/etc/kvm/pwd"

// Role defines the permission level of a user.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access including user management
	RoleOperator Role = "operator" // KVM control: stream, keyboard, mouse, GPIO
	RoleViewer   Role = "viewer"   // View-only: stream access
)

// Account represents a single user.
type Account struct {
	Username string `json:"username"`
	Password string `json:"password"` // bcrypt hash
	Role     Role   `json:"role"`
	Enabled  bool   `json:"enabled"`
	// TokenVersion is embedded in every JWT issued for this account. Bumping it
	// (on logout, disable, delete+recreate, password or role change) invalidates
	// all outstanding tokens for the user. Absent in legacy files -> defaults to 0.
	TokenVersion int `json:"tokenVersion"`
}

// legacyAccount mirrors the old single-user format for migration.
type legacyAccount struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GetAccounts returns all accounts, migrating from legacy format if needed.
func GetAccounts() ([]Account, error) {
	if _, err := os.Stat(AccountFile); err == nil {
		return readAccountsFile()
	}
	if _, err := os.Stat(LegacyAccountFile); err == nil {
		return migrateLegacyAccount()
	}
	return []Account{defaultAdminAccount()}, nil
}

// GetAccountByUsername returns a specific account or an error if not found.
func GetAccountByUsername(username string) (*Account, error) {
	accounts, err := GetAccounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		if a.Username == username {
			acc := a
			return &acc, nil
		}
	}
	return nil, errors.New("user not found")
}

// SaveAccounts writes the full account list to disk atomically: it writes to a
// temp file in the same directory, fsyncs it, then renames over the target and
// fsyncs the directory. A crash or power loss can therefore never leave a
// truncated or half-written accounts file behind.
func SaveAccounts(accounts []Account) error {
	data, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(AccountFile)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".accounts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail out before the rename; a no-op afterwards.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, AccountFile); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// BumpTokenVersion increments a user's token version, invalidating every JWT
// previously issued to them.
func BumpTokenVersion(username string) error {
	accounts, err := GetAccounts()
	if err != nil {
		return err
	}
	for i, a := range accounts {
		if a.Username == username {
			accounts[i].TokenVersion++
			return SaveAccounts(accounts)
		}
	}
	return errors.New("user not found")
}

// randomTokenVersion returns a random positive int used as the initial token
// version for freshly created accounts. Randomising it means a token minted for
// a deleted user cannot validate against a later account that happens to reuse
// the same username.
func randomTokenVersion() int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		return int(time.Now().UnixNano() & 0x7fffffff)
	}
	return int(n.Int64()) + 1
}

// AddAccount appends a new user. Returns error if username exists.
func AddAccount(username, plainPassword string, role Role) error {
	accounts, err := GetAccounts()
	if err != nil {
		return err
	}
	for _, a := range accounts {
		if a.Username == username {
			return errors.New("username already exists")
		}
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	accounts = append(accounts, Account{
		Username:     username,
		Password:     string(hashed),
		Role:         role,
		Enabled:      true,
		TokenVersion: randomTokenVersion(),
	})
	return SaveAccounts(accounts)
}

// UpdateAccountPassword changes a user's password (expects bcrypt hash).
func UpdateAccountPassword(username, hashedPassword string) error {
	accounts, err := GetAccounts()
	if err != nil {
		return err
	}
	for i, a := range accounts {
		if a.Username == username {
			accounts[i].Password = hashedPassword
			accounts[i].TokenVersion++ // invalidate existing sessions
			return SaveAccounts(accounts)
		}
	}
	return errors.New("user not found")
}

// UpdateAccountRole changes a user's role.
func UpdateAccountRole(username string, role Role) error {
	accounts, err := GetAccounts()
	if err != nil {
		return err
	}
	for i, a := range accounts {
		if a.Username == username {
			accounts[i].Role = role
			accounts[i].TokenVersion++ // force re-auth with the new role
			return SaveAccounts(accounts)
		}
	}
	return errors.New("user not found")
}

// SetAccountEnabled enables or disables a user account.
func SetAccountEnabled(username string, enabled bool) error {
	accounts, err := GetAccounts()
	if err != nil {
		return err
	}
	for i, a := range accounts {
		if a.Username == username {
			accounts[i].Enabled = enabled
			if !enabled {
				accounts[i].TokenVersion++ // kill sessions of a disabled user
			}
			return SaveAccounts(accounts)
		}
	}
	return errors.New("user not found")
}

// DeleteAccount removes a user. The last admin account cannot be deleted.
func DeleteAccount(username string) error {
	accounts, err := GetAccounts()
	if err != nil {
		return err
	}
	var target *Account
	for _, a := range accounts {
		if a.Username == username {
			acc := a
			target = &acc
			break
		}
	}
	if target == nil {
		return errors.New("user not found")
	}
	if target.Role == RoleAdmin {
		adminCount := 0
		for _, a := range accounts {
			if a.Role == RoleAdmin && a.Enabled {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return errors.New("cannot delete the last admin account")
		}
	}
	filtered := make([]Account, 0, len(accounts)-1)
	for _, a := range accounts {
		if a.Username != username {
			filtered = append(filtered, a)
		}
	}
	return SaveAccounts(filtered)
}

// CompareAccount checks credentials and returns the account on success.
func CompareAccount(username, plainPassword string) (*Account, bool) {
	account, err := GetAccountByUsername(username)
	if err != nil || account == nil || !account.Enabled {
		return nil, false
	}
	decoded, err := utils.DecodeDecrypt(plainPassword)
	if err != nil || decoded == "" {
		return nil, false
	}
	if err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(decoded)); err != nil {
		// Compatibility with old plain-hashed storage
		oldHash, _ := utils.DecodeDecrypt(account.Password)
		if oldHash != decoded {
			return nil, false
		}
	}
	return account, true
}

// DeviceOwner is the account whose password is synchronised to the Linux root
// user (and therefore SSH). It is the device owner: only the owner itself may
// change its password, role, or enabled state, or delete it. Otherwise a second
// admin could change this account and hijack root.
const DeviceOwner = "admin"

// IsDeviceOwner reports whether username is the protected device-owner account.
func IsDeviceOwner(username string) bool {
	return username == DeviceOwner
}

// VerifyCurrentPassword checks an encrypted candidate password against the
// stored hash for a user. Used to confirm identity on self-service password
// changes so a hijacked or unattended session cannot silently change it.
func VerifyCurrentPassword(username, encrypted string) bool {
	account, err := GetAccountByUsername(username)
	if err != nil || account == nil {
		return false
	}
	decoded, err := utils.DecodeDecrypt(encrypted)
	if err != nil || decoded == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(decoded)) == nil
}

// IsValidRole checks whether a role string is valid.
func IsValidRole(r Role) bool {
	return r == RoleAdmin || r == RoleOperator || r == RoleViewer
}

func readAccountsFile() ([]Account, error) {
	data, err := os.ReadFile(AccountFile)
	if err != nil {
		return nil, err
	}
	var accounts []Account
	if err = json.Unmarshal(data, &accounts); err != nil {
		log.Errorf("failed to unmarshal accounts: %s", err)
		return nil, err
	}
	return accounts, nil
}

func migrateLegacyAccount() ([]Account, error) {
	data, err := os.ReadFile(LegacyAccountFile)
	if err != nil {
		return nil, err
	}
	var legacy legacyAccount
	if err = json.Unmarshal(data, &legacy); err != nil {
		// Fail closed: never silently fall back to admin/admin on corrupt data.
		log.Errorf("failed to unmarshal legacy account: %s", err)
		return nil, errors.New("legacy account file is corrupt")
	}
	account := Account{
		Username: legacy.Username,
		Password: legacy.Password,
		Role:     RoleAdmin,
		Enabled:  true,
	}
	accounts := []Account{account}
	if saveErr := SaveAccounts(accounts); saveErr == nil {
		_ = os.Remove(LegacyAccountFile)
		log.Infof("migrated legacy account '%s' to multi-user format", legacy.Username)
	}
	return accounts, nil
}

func defaultAdminAccount() Account {
	hashed, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	return Account{
		Username: "admin",
		Password: string(hashed),
		Role:     RoleAdmin,
		Enabled:  true,
	}
}
