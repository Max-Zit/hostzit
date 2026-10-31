package hosting

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PHP options of an account for one PHP version (like cPanel's "Select PHP
// Extensions" and "MultiPHP INI Editor"): extensions the account switches
// off and php.ini values from an allow-list. Limits of the package
// (memory, upload size) can only be lowered.

// PHPOptions are the choices of an account for one PHP version.
type PHPOptions struct {
	// Disabled are extensions (names as in mods-available) not loaded.
	Disabled []string `json:"disabled,omitempty"`
	// INI are php.ini values (see INIKeys).
	INI map[string]string `json:"ini,omitempty"`
}

var extNameRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// INIKey describes one php.ini value a customer may set.
type INIKey struct {
	Name string
	Kind string // bool | int | size | text
	Min  int
	Max  int
	// Admin keys are set with php_admin_value (scripts cannot raise them).
	Admin bool
}

// INIKeys are the php.ini values customers may set.
var INIKeys = []INIKey{
	{Name: "memory_limit", Kind: "size", Min: 16, Admin: true},
	{Name: "upload_max_filesize", Kind: "size", Min: 1, Admin: true},
	{Name: "post_max_size", Kind: "size", Min: 1, Admin: true},
	{Name: "max_execution_time", Kind: "int", Min: 1, Max: 300, Admin: true},
	{Name: "max_input_time", Kind: "int", Min: -1, Max: 300},
	{Name: "max_input_vars", Kind: "int", Min: 100, Max: 100000},
	{Name: "session.gc_maxlifetime", Kind: "int", Min: 60, Max: 2592000},
	{Name: "display_errors", Kind: "bool"},
	{Name: "short_open_tag", Kind: "bool"},
	{Name: "allow_url_fopen", Kind: "bool"},
	{Name: "zlib.output_compression", Kind: "bool"},
	{Name: "date.timezone", Kind: "text"},
}

var tzNameRE = regexp.MustCompile(`^[A-Za-z]+(/[A-Za-z0-9_+-]+){0,2}$`)

func iniKey(name string) (INIKey, bool) {
	for _, k := range INIKeys {
		if k.Name == name {
			return k, true
		}
	}
	return INIKey{}, false
}

// CleanINI checks a value; sizes are whole megabytes ("256" or "256M").
func CleanINI(name, v string, l Limits) (string, error) {
	k, ok := iniKey(name)
	if !ok {
		return "", fmt.Errorf("%s cannot be set", name)
	}
	v = strings.TrimSpace(v)
	switch k.Kind {
	case "bool":
		switch strings.ToLower(v) {
		case "on", "1", "true":
			return "on", nil
		case "off", "0", "false":
			return "off", nil
		}
		return "", fmt.Errorf("%s: on or off", name)
	case "int":
		n, err := strconv.Atoi(v)
		if err != nil || n < k.Min || n > k.Max {
			return "", fmt.Errorf("%s: a number from %d to %d", name, k.Min, k.Max)
		}
		return strconv.Itoa(n), nil
	case "size":
		n, err := strconv.Atoi(strings.TrimSuffix(strings.ToUpper(v), "M"))
		max := l.PHPMemoryMB
		if name != "memory_limit" {
			max = l.UploadMB
		}
		if err != nil || n < k.Min || max > 0 && n > max {
			return "", fmt.Errorf("%s: %d to %d MB (your package)", name, k.Min, max)
		}
		return strconv.Itoa(n) + "M", nil
	case "text":
		if !tzNameRE.MatchString(v) {
			return "", fmt.Errorf("%s: a time zone such as Europe/Belgrade", name)
		}
		return v, nil
	}
	return "", errors.New("unknown kind")
}

// Validate checks the options against the package limits.
func (o PHPOptions) Validate(l Limits) error {
	for _, e := range o.Disabled {
		if !extNameRE.MatchString(e) {
			return fmt.Errorf("invalid extension name %q", e)
		}
	}
	for k, v := range o.INI {
		c, err := CleanINI(k, v, l)
		if err != nil {
			return err
		}
		if c != v {
			return fmt.Errorf("%s: write it as %s", k, c)
		}
	}
	return nil
}

// iniLines are the pool lines of the account's own values (after the
// package's, so they win).
func (o PHPOptions) iniLines() string {
	keys := make([]string, 0, len(o.INI))
	for k := range o.INI {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		kd, _ := iniKey(k)
		v := o.INI[k]
		switch {
		case kd.Kind == "bool" && kd.Admin:
			fmt.Fprintf(&b, "php_admin_flag[%s] = %s\n", k, v)
		case kd.Kind == "bool":
			fmt.Fprintf(&b, "php_flag[%s] = %s\n", k, v)
		case kd.Admin:
			fmt.Fprintf(&b, "php_admin_value[%s] = %s\n", k, v)
		default:
			fmt.Fprintf(&b, "php_value[%s] = %s\n", k, v)
		}
	}
	return b.String()
}

// PHPScanDir is the folder (inside the cage) with the extensions an
// account loads for a version: links to Debian's mods-available.
func PHPScanDir(version string) string {
	return "/.hz/php" + strings.ReplaceAll(version, ".", "") + ".d"
}
