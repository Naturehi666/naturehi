package chromium

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"

	"searchall3.5/tuozhan/liulanqi/browingdata"
	"searchall3.5/tuozhan/liulanqi/item"
	"searchall3.5/tuozhan/liulanqi/utils/fileutil"
	"searchall3.5/tuozhan/liulanqi/utils/typeutil"
)

type Chromium struct {
	name        string
	storage     string
	profilePath string
	masterKey   []byte
	items       []item.Item
	itemPaths   map[item.Item]string
}

// New create instance of Chromium browser, fill item's path if item is existed.
func New(name, storage, profilePath string, items []item.Item) ([]*Chromium, error) {
	c := &Chromium{
		name:        name,
		storage:     storage,
		profilePath: profilePath,
		items:       items,
	}
	multiItemPaths, err := c.userItemPaths(c.profilePath, c.items)
	if err != nil {
		return nil, err
	}
	chromiumList := make([]*Chromium, 0, len(multiItemPaths))
	for user, itemPaths := range multiItemPaths {
		chromiumList = append(chromiumList, &Chromium{
			name:      fileutil.BrowserName(name, user),
			items:     typeutil.Keys(itemPaths),
			itemPaths: itemPaths,
			storage:   storage,
		})
	}
	return chromiumList, nil
}

func (c *Chromium) Name() string {
	return c.name
}

func (c *Chromium) BrowsingData(isFullExport bool, name string) (*browingdata.Data, error) {
	items := c.items
	if !isFullExport {
		items = item.FilterSensitiveItems(c.items)
	}

	data := browingdata.New(items)

	if err := c.copyItemToLocal(); err != nil {
		return nil, err
	}

	masterKey, err := c.GetMasterKey()
	if err != nil {
		return nil, err
	}

	c.masterKey = masterKey
	if err := data.Recovery(c.masterKey, name); err != nil {
		return nil, err
	}

	return data, nil
}

/*func (c *Chromium) copyItemToLocal() error {
	for i, path := range c.itemPaths {
		filename := i.String()
		var err error
		switch {
		case fileutil.IsDirExists(path):
			if i == item.ChromiumLocalStorage {
				err = fileutil.CopyDir(path, filename, "lock")
			} else if i == item.ChromiumSessionStorage {
				err = fileutil.CopyDir(path, filename, "lock")
			} else if i == item.ChromiumExtension {
				err = fileutil.CopyDirHasSuffix(path, filename, "manifest.json")
			}
		case i == item.ChromiumCookie: // Add this condition for ChromiumCookie
			switch runtime.GOOS {
			case "windows":
				if fileutil.CheckIfElevated() {

					npath := fileutil.EnsureNTFSPath(path)
					npathRela := strings.Join(npath[1:], "//")
					err = fileutil.TryRetrieveFile(npath[0], npathRela, filename)

				} else {
					err = fileutil.CopyFile(path, filename)

				}
			default:
				err = fileutil.CopyFile(path, filename)

			}

		default:
			err = fileutil.CopyFile(path, filename)
		}
		if err != nil {
			return err
		}
	}
	return nil
}*/

func (c *Chromium) copyItemToLocal() error {
	for i, path := range c.itemPaths {
		filename := i.String() // 使用i的.String()方法来生成filename
		var err error

		if fileutil.IsDirExists(path) {
			// 处理目录类型的项目
			switch i {
			case item.ChromiumLocalStorage, item.ChromiumSessionStorage:
				// LocalStorage和SessionStorage使用相同的复制逻辑
				err = fileutil.CopyDir(path, filename, "lock")
			case item.ChromiumExtension:
				// 对Chrome扩展，需确保manifest.json存在
				manifestPath := filepath.Join(path, "manifest.json")
				if fileutil.IsFileExists(manifestPath) {
					err = fileutil.CopyDirHasSuffix(path, filename, "manifest.json")
				} else {
					// 如果manifest.json不存在，跳过当前项
					continue
				}
			default:
				// 其他目录类型的项直接复制
				err = fileutil.CopyDir(path, filename, "")
			}
		} else if i == item.ChromiumCookie {
			// 特殊处理ChromiumCookie
			switch runtime.GOOS {
			case "windows":
				if fileutil.CheckIfElevated() {
					// 高权限下的处理流程
					npath := fileutil.EnsureNTFSPath(path)
					npathRela := strings.Join(npath[1:], "//")
					err = fileutil.TryRetrieveFile(npath[0], npathRela, filename)
				} else {
					// 低权限下简单复制文件
					err = fileutil.CopyFile(path, filename)
				}
			default:
				// 非Windows系统下的处理
				err = fileutil.CopyFile(path, filename)
			}
		} else {
			// 默认情况下，尝试复制文件
			err = fileutil.CopyFile(path, filename)
		}

		if err != nil {
			return err //改动的地方
		}
	}
	return nil
}

// userItemPaths return a map of user to item path, map[profile 1][item's name & path key pair]
func (c *Chromium) userItemPaths(profilePath string, items []item.Item) (map[string]map[item.Item]string, error) {
	multiItemPaths := make(map[string]map[item.Item]string)
	parentDir := fileutil.ParentDir(profilePath)
	err := filepath.Walk(parentDir, chromiumWalkFunc(items, multiItemPaths))
	if err != nil {
		return nil, err //改动的地方
	}
	var keyPath string
	var dir string
	for userDir, v := range multiItemPaths {
		for _, p := range v {
			if strings.HasSuffix(p, item.ChromiumKey.FileName()) {
				keyPath = p
				dir = userDir
				break
			}
		}
	}
	t := make(map[string]map[item.Item]string)
	for userDir, v := range multiItemPaths {
		if userDir == dir {
			continue
		}
		t[userDir] = v
		t[userDir][item.ChromiumKey] = keyPath
		fillLocalStoragePath(t[userDir], item.ChromiumLocalStorage)
	}
	return t, nil
}

// chromiumWalkFunc return a filepath.WalkFunc to find item's path
func chromiumWalkFunc(items []item.Item, multiItemPaths map[string]map[item.Item]string) filepath.WalkFunc {
	return func(path string, info fs.FileInfo, err error) error {

		// 确保info不为nil，这是必要的，因为如果err为nil且info也为nil，可能会导致后续调用info.Name()时发生nil指针解引用错误
		if err != nil || info == nil {
			return nil // 返回err，可能会停止遍历，根据情况决定是否返回nil或err
		} //改动的地方
		for _, v := range items {
			if info.Name() == v.FileName() {
				if strings.Contains(path, "System Profile") {
					continue
				}
				profileFolder := fileutil.ParentBaseDir(path)
				if strings.Contains(filepath.ToSlash(path), "/Network/Cookies") {
					profileFolder = fileutil.BaseDir(strings.ReplaceAll(filepath.ToSlash(path), "/Network/Cookies", ""))
				}
				if _, exist := multiItemPaths[profileFolder]; exist {
					multiItemPaths[profileFolder][v] = path
				} else {
					multiItemPaths[profileFolder] = map[item.Item]string{v: path}
				}
			}
		}
		return nil
	}
}

func fillLocalStoragePath(itemPaths map[item.Item]string, storage item.Item) {
	if p, ok := itemPaths[item.ChromiumHistory]; ok {
		lsp := filepath.Join(filepath.Dir(p), storage.FileName())
		if fileutil.IsDirExists(lsp) {
			itemPaths[item.ChromiumLocalStorage] = lsp
		}
	}
}
