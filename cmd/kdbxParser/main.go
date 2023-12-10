package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"kdbxParser/pkg/kdbx"
	"log"
	"os"
)

func main() {
	parser := argparse.NewParser("kdbxParser", "Obtain metadata from a KeePass file")
	parser.ExitOnHelp(true)

	targetFile := parser.String("f", "file", &argparse.Options{Required: true, Help: "Path to the keepass file"})

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

	f := kdbx.Parse(file)
	fmt.Println(f)
}
