package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"kdbxParser/pkg/kdbx"

	"github.com/akamensky/argparse"
)

func main() {
	parser := argparse.NewParser("kdbxParser", "Obtain metadata from a KeePass file")
	parser.ExitOnHelp(true)

	targetFile := parser.String("f", "file", &argparse.Options{Required: true, Help: "Path to the keepass file"})
	useJSON := parser.Flag("", "json", &argparse.Options{Required: false, Help: "Print the result as a json string", Default: false})
	prettifyJSON := parser.Flag("p", "pretty", &argparse.Options{Required: false, Help: "Prettify the json output", Default: false})

	if err := parser.Parse(os.Args); err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// read content of targetFile
	file, err := os.Open(*targetFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// If the file is very large, this could be a problem
	content, readErr := io.ReadAll(file)
	if readErr != nil {
		log.Fatal(readErr)
	}
	f := kdbx.ParseFromBytes(content)

	if *useJSON {
		// Print the result as a json string
		if *prettifyJSON {
			fmt.Println(f.JSONPretty())
			return
		}
		fmt.Println(f.JSON())
		return
	} else {
		// Just use the stringer to print the struct
		fmt.Println(f)
	}
}
