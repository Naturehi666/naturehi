package flagsearch

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"searchall3.5/search"
	"searchall3.5/tuozhan/liulanqi"
	"searchall3.5/tuozhan/liulanqi/browser"
	"strings"
)

func Banner() {
	fmt.Println(`
 __
(_  _  _  __ _ |_  _  |  |
__)(/_(_| | (_ | |(_| |  |
        verson:3.5.11
                     `)
}

func FlagSearchall() {

	app := cli.NewApp()
	app.Name = "searchall"
	app.Usage = "Search for files or execute browser password."
	Banner()

	app.Commands = []*cli.Command{
		{
			Name:  "search",
			Usage: "Search for files",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "p",
					Usage: "The path to search for files",
				},
				&cli.StringFlag{
					Name:  "r",
					Usage: "Custom regular expressions",
				},
				&cli.StringFlag{
					Name:  "s",
					Usage: "Custom strings (pre-compiled into regex)",
				},
				&cli.BoolFlag{
					Name:  "u",
					Usage: "Only use custom regex and strings for searching",
				},
				&cli.StringFlag{
					Name:  "e",
					Usage: "Custom extension",
				},
				&cli.BoolFlag{
					Name:  "n",
					Usage: "Only use custom extension for searching",
				},
				&cli.Int64Flag{
					Name:  "size",
					Usage: "file size limit in bytes(Default 3M)",
					Value: 3 * 1024 * 1024,
				},
				&cli.IntFlag{
					Name:  "char",
					Usage: "character limit(Default 200)",
					Value: 200,
				},
			},
			Action: func(c *cli.Context) error {

				searchPath := c.String("p")
				userOnlyFlag := c.Bool("u")
				userRegexes := c.String("r")
				userStrings := c.String("s")
				userExtension := c.String("e")
				userOnlyExten := c.Bool("n")
				size := c.Int64("size")
				char := c.Int("char")

				if searchPath != "" {
					var userRegexList []string

					if userRegexes != "" {
						inputs := strings.Split(userRegexes, ",")
						userRegexList = processUserString(inputs)

					} else if userStrings != "" {
						inputs := strings.Split(userStrings, ",")
						userRegexList = processUserString1(inputs)

					}
					if size != 3 {
						size = size * 1024 * 1024

					}

					if char != 200 {

						char = char
					}

					search.Searchall(searchPath, userRegexList, userOnlyFlag, userExtension, userOnlyExten, size, char)
				} else {
					cli.ShowSubcommandHelp(c)
				}
				return nil
			},
		},
		{
			Name:  "browser",
			Usage: "browser password",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "b",
					Usage: "Available browsers: all|" + browser.Names(),
				},
				&cli.BoolFlag{
					Name:  "z",
					Usage: "Compress browser results to zip",
				},
				&cli.StringFlag{
					Name:  "p",
					Usage: "custom profile dir path",
				},
			},
			Action: func(c *cli.Context) error {

				browserFlag := c.String("b")
				zipFlag := c.Bool("z")
				profilePath := c.String("p")
				if browserFlag != "" {
					liulanqi.Execute(browserFlag, profilePath)

					if zipFlag {
						err := liulanqi.CompressResult()
						if err != nil {
							fmt.Println(err)
						}
					}
				} else {
					cli.ShowSubcommandHelp(c)
				}
				return nil
			},
		},
	}

	app.RunAndExitOnError()
}
