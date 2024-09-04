package liulanqi

import (
	"fmt"
	"os"
	"path/filepath"

	"searchall3.5/tuozhan/liulanqi/browser"
	"searchall3.5/tuozhan/liulanqi/log"
	"searchall3.5/tuozhan/liulanqi/utils/fileutil"
)

var (
	outputDir    string
	outputFormat string
	isFullExport bool
)

func Execute(browserFlag string, profilePath string) {

	outputDir = "results"
	outputFormat = "csv"

	isFullExport = true

	browsers, err := browser.PickBrowsers(browserFlag, profilePath)

	if err != nil {
		log.Error(err)

	}

	for _, b := range browsers {
		data, err := b.BrowsingData(isFullExport)
		if err != nil {
			log.Error(err)
			continue
		}
		data.Output(outputDir, b.Name(), outputFormat)
	}

	if _, err := os.Stat(outputDir); err == nil {
		log.Notice("请查看当前目录生成了文件夹:results")
	} else {

	}
}

func CompressResult() error {
	if err := fileutil.CompressDir(outputDir); err != nil {
		return fmt.Errorf("压缩失败：%s", err.Error())
	}

	dir, _ := os.Getwd()
	log.Noticef("请查看当前目录生成压缩包: %s", filepath.Join(dir, "\\results\\results.zip"))

	return nil
}
