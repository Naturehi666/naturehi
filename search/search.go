package search

import (
	"bytes"
	"fmt"
	"golang.org/x/text/transform"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"searchall3.5/guize"
	"searchall3.5/guolv"
	"searchall3.5/jiexi"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

func compileRegexes(regexList []string) ([]*regexp.Regexp, error) {
	var compiledRegexes []*regexp.Regexp

	for _, r := range regexList {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, err
		}
		compiledRegexes = append(compiledRegexes, re)

	}

	return compiledRegexes, nil
}

func SearchConfigFiles(path string, info os.FileInfo, allRegexes []*regexp.Regexp, customFileTypeList string, extenOnlyFlag bool, sizeLimit int64, charLimit int) ([]string, error) {

	var results []string

	size := info.Size()

	if info.IsDir() && size > sizeLimit {
		return results, nil
	}
	/*if size > sizeLimit {
		return results, nil
	}*/
	ext := filepath.Ext(path)

	if ext == "" { // 如果文件没有拓展名，则跳过
		return results, nil
	}
	fileType := ""

	if extenOnlyFlag == false {
		UpdateFileTypes(guize.FileTypes, "custom", customFileTypeList)
		for k, v := range guize.FileTypes {
			if strings.Contains(v, ext+",") {
				fileType = k
				break
			}
		}
	} else {
		UpdateFileTypes(guize.CusFileTypes, "custom", customFileTypeList)
		for k, v := range guize.CusFileTypes {
			if strings.Contains(v, ext+",") {
				fileType = k
				break
			}
		}

	}

	if fileType == "" {
		return results, nil
	}

	fileContent, err := ioutil.ReadFile(path)
	if err != nil {

		return results, err
	}
	enc, err := jiexi.DetectEncoding(fileContent)
	if err != nil {
		return results, nil
	}

	reader := transform.NewReader(bytes.NewReader(fileContent), enc.NewDecoder())
	lines, err := ioutil.ReadAll(reader)
	if err != nil {
		return results, err
	}

	var matchedContents []string

	for _, line := range bytes.Split(lines, []byte{'\n'}) {

		//过滤掉包含黑名单中任意一个元素的行
		if guolv.ContainsAny(line, guize.Blacklist) {

			continue

		}

		lineStr := strings.TrimSpace(string(line))
		if len(lineStr) == 0 {
			continue
		}

		var matches []string
		for _, regex := range allRegexes { // 新增代码
			match := regex.FindStringSubmatch(lineStr)
			if len(match) > 1 {
				matches = append(matches, match[1])
			}
		}
		if len(matches) == 0 {
			continue
		}

		matchedContent := fmt.Sprintf("%s\n", lineStr)

		if utf8.RuneCountInString(matchedContent) <= charLimit {
			matchedContents = append(matchedContents, matchedContent)
		}

	}

	if len(matchedContents) > 0 {

		var buffer bytes.Buffer

		lines := strings.Split(strings.TrimSpace(strings.Join(matchedContents, "\n")), "\n")

		// 找到最长的行
		maxLen := 0
		for _, line := range lines {
			if length := len(line); length > maxLen {
				maxLen = length
			}
		}

		// 写入文件路径
		absPath, err := filepath.Abs(path)
		if err != nil {
			return results, err
		}
		buffer.WriteString(fmt.Sprintf("File: %s\n", absPath))

		// 将所有行都填充到相同的长度
		for _, line := range lines {

			for _, line := range strings.Split(line, "\n") {
				for _, regex := range guize.TeZhengList {
					re := regexp.MustCompile(regex)
					if re.MatchString(line) {
						fmt.Printf("\n%s\n", line)

					}
				}
			}

			prefix := strings.Repeat(" ", 2)
			paddedLine := fmt.Sprintf("%-*s\n", maxLen, line)

			buffer.WriteString(prefix)
			buffer.WriteString(paddedLine)
		}

		results = append(results, buffer.String())
	}

	return results, nil
}

func Searchall(path string, userRegexList []string, userOnlyFlag bool, customFileTypeList string, extenOnlyFlag bool, sizeLimit int64, charLimit int) {

	//获取cpu核心数
	numCores := runtime.NumCPU() // 根据系统的能力调整此值

	maxWorkers := numCores / 2
	if maxWorkers <= 1 {
		maxWorkers = 1
	}
	numWorkers := maxWorkers

	//runtime.GOMAXPROCS(runtime.NumCPU() / 4)

	outputFile := "search.txt"
	outputFilePath, err := filepath.Abs(outputFile)

	if _, err := os.Stat(path); os.IsNotExist(err) { // 检查路径是否存在
		fmt.Printf("路径 %s 不存在，请输入正确路径\n", path)
		return
	}

	if err != nil {
		fmt.Println("Error getting absolute path of output file:", err)
		return
	}

	if path == outputFilePath {
		fmt.Println("Output file cannot be the same as search path.")
		return
	}

	var CompiledRegexes []*regexp.Regexp

	if userOnlyFlag {
		CompiledRegexes, err = compileRegexes(userRegexList)
	} else {
		allRegexes := append(guize.RegexList, userRegexList...)
		CompiledRegexes, err = compileRegexes(allRegexes)
	}

	if err != nil {
		fmt.Println("Error compiling regexes:", err)
		return
	}

	fmt.Println("Searching files in", path)
	fmt.Println("This may take a while. Please wait...")
	fmt.Printf("Results will be saved to %s\n", outputFilePath)

	resultChan := make(chan []string)
	errChan := make(chan error)
	fastCodeHistoryChan := make(chan string)

	var wg sync.WaitGroup
	var mu sync.Mutex
	pool := make(chan struct{}, maxWorkers)

	go func() {

		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			pool <- struct{}{} // 获取一个工作者槽位
			defer func() { <-pool }()
			//fmt.Println("path:", path)

			if err != nil {

				return nil
			}
			if info.IsDir() {
				for _, name := range guize.DirNamesToSkip {
					if info.Name() == name {
						return filepath.SkipDir
					}
				}
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				fmt.Println("Error getting absolute path:", err)
				return nil
			}

			if absPath == outputFilePath {
				return nil
			}

			if path == outputFilePath {
				return nil
			}

			res, err := SearchConfigFiles(path, info, CompiledRegexes, customFileTypeList, extenOnlyFlag, sizeLimit, charLimit)
			if err != nil {
				errChan <- err
				return nil
			}
			if len(res) > 0 {
				resultChan <- res
			}

			ProcessFile(info, path, absPath, resultChan, fastCodeHistoryChan, errChan)

			return nil

		})
		if err != nil {
			errChan <- err
		}

		close(resultChan)
		close(fastCodeHistoryChan)

	}()

	file, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		return
	}
	defer func() {
		err := file.Close()
		if err != nil {
			fmt.Println("Error closing output file:", err)
		}
	}()

	writeWorkerCh := make(chan string, numWorkers)

	// 启动文件写入工作goroutine
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for result := range writeWorkerCh {
				mu.Lock()
				_, err = file.WriteString(result + "\n")
				mu.Unlock()
				if err != nil {
					fmt.Println("Error writing to output file:", err)
					return
				}
			}
		}()
	}

	start := time.Now()

	if err != nil {
		fmt.Println("Error counting files:", err)
		return
	}

	numScannedFiles := 0

	for {
		select {
		case results, ok := <-resultChan:
			if !ok {
				// channel has been closed
				end := time.Now()
				fmt.Printf(fmt.Sprintf("\nsearch finished at %s. Total search time: %v.\n", end.Format(time.RFC3339), end.Sub(start)))
				close(writeWorkerCh)
				wg.Wait()
				return
			}
			for _, result := range results {
				writeWorkerCh <- result
			}

			// 增加已处理文件计数并更新进度条
			numScannedFiles++
			prefix := fmt.Sprintf("Scanning valid files... %d", numScannedFiles)
			fmt.Printf("\r%s", prefix)
			fmt.Print("\033[0K") // 清除当前光标位置到行尾的内容

		case fastCodeHistory, ok := <-fastCodeHistoryChan:
			if !ok {
				return
			}
			writeWorkerCh <- fastCodeHistory

		case err := <-errChan:
			if err == nil {
				fmt.Println("Error searching file:", err)
			}

		}
	}
}
