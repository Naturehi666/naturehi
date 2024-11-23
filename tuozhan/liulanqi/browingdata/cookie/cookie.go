package cookie

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"searchall3.5/tuozhan/liulanqi/crypto"
	"sort"
	"strconv"
	"strings"
	"time"

	// import sqlite3 driver
	_ "github.com/mattn/go-sqlite3"

	"searchall3.5/tuozhan/liulanqi/item"
	"searchall3.5/tuozhan/liulanqi/log"
	"searchall3.5/tuozhan/liulanqi/utils/typeutil"
)

type ChromiumCookie []Cookie

type Cookie struct {
	Host         string
	Path         string
	KeyName      string
	encryptValue []byte
	Value        string
	IsSecure     bool
	IsHTTPOnly   bool
	HasExpire    bool
	IsPersistent bool
	CreateDate   time.Time
	ExpireDate   time.Time
}

const (
	queryChromiumCookie = `SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc, is_secure, is_httponly, has_expires, is_persistent FROM cookies`
)

func (c *ChromiumCookie) Parse(masterKey []byte, name string) error {

	db, err := sql.Open("sqlite3", item.TempChromiumCookie)
	if err != nil {
		return err
	}
	defer os.Remove(item.TempChromiumCookie)
	defer db.Close()

	rows, err := db.Query(queryChromiumCookie)
	fmt.Println("请稍等一会，有一点点慢")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			key, host, path                               string
			isSecure, isHTTPOnly, hasExpire, isPersistent int
			createDate, expireDate                        int64
			value, encryptValue                           []byte
		)
		if err = rows.Scan(&key, &encryptValue, &host, &path, &createDate, &expireDate, &isSecure, &isHTTPOnly, &hasExpire, &isPersistent); err != nil {
			log.Warn(err)

		}

		cookie := Cookie{
			KeyName:      key,
			Host:         host,
			Path:         path,
			encryptValue: encryptValue,
			IsSecure:     typeutil.IntToBool(isSecure),
			IsHTTPOnly:   typeutil.IntToBool(isHTTPOnly),
			HasExpire:    typeutil.IntToBool(hasExpire),
			IsPersistent: typeutil.IntToBool(isPersistent),
			CreateDate:   typeutil.TimeEpoch(createDate),
			ExpireDate:   typeutil.TimeEpoch(expireDate),
		}

		if strings.Contains(name, "chrome") {

			targetVersion := "130.0.6723.70"
			currentVersion := c.Version()
			versionComparison := c.compareVersions(currentVersion, targetVersion)

			if versionComparison == 1 {
				// For versions higher than the target version
				masterKey, _ := DecryptChromeKey()
				value, _ := DecryptCookieValue(encryptValue, masterKey)

				cookie.Value = value
				*c = append(*c, cookie)

			} else {
				// For versions equal to or lower than the target version
				if len(masterKey) == 0 {
					value, err = crypto.DPAPI(encryptValue)
				} else {
					value, err = crypto.DecryptPass(masterKey, encryptValue)
				}

				if err != nil {
					log.Error(err)

				}

				cookie.Value = string(value)
				*c = append(*c, cookie)

			}

		} /*else {

			if len(masterKey) == 0 {
				value, err = crypto.DPAPI(encryptValue)
			} else {
				value, err = crypto.DecryptPass(masterKey, encryptValue)
			}

			if err != nil {
				log.Error(err)

			}

			cookie.Value = string(value)
			*c = append(*c, cookie)

		}*/

	}

	sort.Slice(*c, func(i, j int) bool {
		return (*c)[i].CreateDate.After((*c)[j].CreateDate)
	})
	return nil
}

func (c *ChromiumCookie) Name() string {
	return "cookie"
}

func (c *ChromiumCookie) Len() int {
	return len(*c)
}

func (c *ChromiumCookie) Version() string {

	var cmd *exec.Cmd
	cmd = exec.Command("cmd", "/C", "reg", "query", `HKEY_CURRENT_USER\Software\Google\Chrome\BLBeacon`, "/v", "version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	var version string

	for _, line := range lines {
		if strings.Contains(line, "version") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				version = parts[len(parts)-1]
			}
			break
		}
	}

	return version
}

func (c *ChromiumCookie) compareVersions(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		num1, _ := strconv.Atoi(v1Parts[i])
		num2, _ := strconv.Atoi(v2Parts[i])

		if num1 < num2 {
			return -1
		}
		if num1 > num2 {
			return 1
		}
	}

	if len(v1Parts) < len(v2Parts) {
		return -1
	}
	if len(v1Parts) > len(v2Parts) {
		return 1
	}

	return 0
}

type FirefoxCookie []Cookie

const (
	queryFirefoxCookie = `SELECT name, value, host, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookies`
)

func (f *FirefoxCookie) Parse(_ []byte, name string) error {
	db, err := sql.Open("sqlite3", item.TempFirefoxCookie)
	if err != nil {
		return err
	}
	defer os.Remove(item.TempFirefoxCookie)
	defer db.Close()

	rows, err := db.Query(queryFirefoxCookie)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name, value, host, path string
			isSecure, isHTTPOnly    int
			creationTime, expiry    int64
		)
		if err = rows.Scan(&name, &value, &host, &path, &creationTime, &expiry, &isSecure, &isHTTPOnly); err != nil {
			log.Warn(err)
		}
		*f = append(*f, Cookie{
			KeyName:    name,
			Host:       host,
			Path:       path,
			IsSecure:   typeutil.IntToBool(isSecure),
			IsHTTPOnly: typeutil.IntToBool(isHTTPOnly),
			CreateDate: typeutil.TimeStamp(creationTime / 1000000),
			ExpireDate: typeutil.TimeStamp(expiry),
			Value:      value,
		})
	}

	sort.Slice(*f, func(i, j int) bool {
		return (*f)[i].CreateDate.After((*f)[j].CreateDate)
	})
	return nil
}

func (f *FirefoxCookie) Name() string {
	return "cookie"
}

func (f *FirefoxCookie) Len() int {
	return len(*f)
}
