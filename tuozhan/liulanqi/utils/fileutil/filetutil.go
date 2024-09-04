package fileutil

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	cp "github.com/otiai10/copy"
	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

const (
	NTFSAttrType_Data = 128
	NTFSAttrID_Normal = 0
)

var (
	ErrReturnedNil        = errors.New("result returned nil reference")
	ErrInvalidInput       = errors.New("invalid input")
	ErrDeviceInaccessible = errors.New("raw device is not accessible")
)

// IsFileExists checks if the file exists in the provided path
func IsFileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// IsDirExists checks if the folder exists
func IsDirExists(folder string) bool {
	info, err := os.Stat(folder)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return info.IsDir()
}

// FilesInFolder returns the filepath contains in the provided folder
func FilesInFolder(dir, filename string) ([]string, error) {
	if !IsDirExists(dir) {
		return nil, errors.New(dir + "folder does not exist")
	}
	var files []string
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() && strings.HasSuffix(path, filename) {
			files = append(files, path)
		}
		return err
	})
	return files, err
}

// ReadFile reads the file from the provided path
func ReadFile(filename string) (string, error) {
	s, err := os.ReadFile(filename)
	return string(s), err
}

// CopyDir copies the directory from the source to the destination
// skip the file if you don't want to copy
func CopyDir(src, dst, skip string) error {
	s := cp.Options{Skip: func(info os.FileInfo, src, dst string) (bool, error) {
		return strings.HasSuffix(strings.ToLower(src), skip), nil
	}}
	return cp.Copy(src, dst, s)
}

// CopyDirHasSuffix copies the directory from the source to the destination
// contain is the file if you want to copy, and rename copied filename with dir/index_filename
func CopyDirHasSuffix(src, dst, suffix string) error {

	var files []string
	err := filepath.Walk(src, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		} //改动的地方
		if !f.IsDir() && strings.HasSuffix(strings.ToLower(f.Name()), suffix) {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for index, file := range files {
		// p = dir/index_file
		p := fmt.Sprintf("%s/%d_%s", dst, index, BaseDir(file))
		err = CopyFile(file, p)
		if err != nil {
			return err
		}

	}
	return nil
}

// CopyFile copies the file from the source to the destination
func CopyFile(src, dst string) error {
	s, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	err = os.WriteFile(dst, s, 0o600)
	if err != nil {
		return err
	}
	return nil
}

// ItemName returns the filename from the provided path
func ItemName(browser, item, ext string) string {
	replace := strings.NewReplacer(" ", "_", ".", "_", "-", "_")
	return strings.ToLower(fmt.Sprintf("%s_%s.%s", replace.Replace(browser), item, ext))
}

func BrowserName(browser, user string) string {
	replace := strings.NewReplacer(" ", "_", ".", "_", "-", "_", "Profile", "user")
	return strings.ToLower(fmt.Sprintf("%s_%s", replace.Replace(browser), replace.Replace(user)))
}

// ParentDir returns the parent directory of the provided path
func ParentDir(p string) string {
	return filepath.Dir(filepath.Clean(p))
}

// BaseDir returns the base directory of the provided path
func BaseDir(p string) string {
	return filepath.Base(p)
}

// ParentBaseDir returns the parent base directory of the provided path
func ParentBaseDir(p string) string {
	return BaseDir(ParentDir(p))
}

// CompressDir compresses the directory into a zip file
func CompressDir(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	b := new(bytes.Buffer)
	zw := zip.NewWriter(b)
	for _, f := range files {
		fw, err := zw.Create(f.Name())
		if err != nil {
			return err
		}
		name := path.Join(dir, f.Name())
		content, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		_, err = fw.Write(content)
		if err != nil {
			return err
		}
		err = os.Remove(name)
		if err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	filename := filepath.Join(dir, fmt.Sprintf("%s.zip", dir))
	outFile, err := os.Create(filepath.Clean(filename))
	if err != nil {
		return err
	}
	_, err = b.WriteTo(outFile)
	if err != nil {
		return err
	}
	return outFile.Close()
}

func EnsureNTFSPath(volFilePath string) []string {
	return strings.Split(volFilePath, "\\")
}

func TryRetrieveFile(volDiskLetter string, filePath string, outFile string) error {

	// check user input
	var IsDiskLetter = regexp.MustCompile(`^[a-zA-Z]:$`).MatchString
	if !IsDiskLetter(volDiskLetter) {
		return ErrInvalidInput
	}

	// use UNC path to access raw device to bypass limitation of file lock
	volFd, err := os.Open("\\\\.\\" + volDiskLetter)
	if err != nil {
		return ErrDeviceInaccessible
	}

	// build a pagedReader for raw device to feed the NTFSContext initializor
	ntfsPagedReader, err := ntfs.NewPagedReader(volFd, 0x1000, 0x10000)
	if err != nil {
		return err
	}

	// build NTFS context for root device
	ntfsVolCtx, err := ntfs.GetNTFSContext(ntfsPagedReader, 0)
	if err != nil {
		return err
	}

	// get volume root
	ntfsVolRoot, err := ntfsVolCtx.GetMFT(5)
	if err != nil {
		return err
	}

	corrFileEntry, err := ntfsVolRoot.Open(ntfsVolCtx, filePath)
	if err != nil {
		return err
	}

	// after found MFT_ENTRY, retrieve file metadata information located in corresponding data-stream attribute
	corrFileInfo, err := corrFileEntry.StandardInformation(ntfsVolCtx)
	if err != nil {
		return err
	}

	fulPath, err := ntfs.GetFullPath(ntfsVolCtx, corrFileEntry)
	if err != nil {
		return err
	}
	err = PrintFileMetadata(corrFileInfo, volDiskLetter+"/"+fulPath)
	if err != nil {
		return err
	}

	corrFileReader, err := ntfs.OpenStream(ntfsVolCtx, corrFileEntry, NTFSAttrType_Data, NTFSAttrID_Normal)
	if err != nil {
		return err
	}

	err = CopyToDestinationFile(corrFileReader, outFile)
	if err != nil {
		return err
	}

	err = ApplyOriginalMetadata(volDiskLetter+"/"+fulPath, corrFileInfo, outFile)
	if err != nil {
		return err
	}

	return nil
}

func ApplyOriginalMetadata(path string, info *ntfs.STANDARD_INFORMATION, dst string) error {
	winFileHd, err := windows.Open(dst, windows.O_RDWR, 0)
	defer windows.CloseHandle(winFileHd)
	if err != nil {
		return err
	}
	// golang official os package does not support Creation Time change due to non-POSIX complaint
	// use windows specific API only.
	cTime4Win := windows.NsecToFiletime(info.Create_time().UnixNano())
	aTime4Win := windows.NsecToFiletime(info.File_accessed_time().UnixNano())
	mTime4Win := windows.NsecToFiletime(info.File_altered_time().UnixNano())
	err = windows.SetFileTime(winFileHd, &cTime4Win, &aTime4Win, &mTime4Win)
	if err != nil {
		return err
	}
	return nil
}

func PrintFileMetadata(stdinfo *ntfs.STANDARD_INFORMATION, fullpath string) error {
	if stdinfo == nil {
		return ErrReturnedNil
	}

	return nil
}

func CopyToDestinationFile(src ntfs.RangeReaderAt, dstfile string) error {
	if src == nil {
		return ErrReturnedNil
	}

	//log.Println("Copying to " + dstfile)
	dstFd, err := os.Create(dstfile)
	defer dstFd.Sync()
	defer dstFd.Close()
	if err != nil {
		return err
	}

	convertedReader := ConvertFromReaderAtToReader(src, 0)

	wBytes, err := io.Copy(dstFd, convertedReader)
	log.Printf("Written %d Bytes to Destination Done. \n", wBytes)
	if err != nil {
		return err
	}

	return nil
}

type readerFromRangedReaderAt struct {
	r      io.ReaderAt
	offset int64
}

func ConvertFromReaderAtToReader(r io.ReaderAt, o int64) *readerFromRangedReaderAt {
	return &readerFromRangedReaderAt{r: r, offset: o}
}

func (rd *readerFromRangedReaderAt) Read(b []byte) (n int, err error) {
	n, err = rd.r.ReadAt(b, rd.offset)
	if n > 0 {
		rd.offset += int64(n)
	}
	return
}

func CheckIfElevated() bool {

	if windows.GetCurrentProcessToken().IsElevated() {

		return true
	}

	fmt.Println("如果谷歌Cookies没有解出来以下有两种方法任选其一即可\n" +
		"1.请提升到管理员权限重新运行命令,谷歌能读取Cookie.\n" +
		"2.请关闭谷歌浏览器重新运行命令,谷歌能读取Cookie\n" +
		"如果解出来了恭喜恭喜！")
	return false
}
