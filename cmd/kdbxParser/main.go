package main

import (
	"flag"
	"fmt"
	"kdbxParser/pkg/kdbx"
	"log"
	"os"
)

func main() {
	targetFile := flag.String("file", "", "Path to kdbx file")
	flag.Parse()

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
