package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"sync"
	// "time"

	color "github.com/fatih/color"
	"github.com/hillu/go-yara"
)

type ScanResult struct {
	URL string
	CPESlice []string
	Matches []yara.MatchRules
}

func main() {
	inputFileName := flag.String("i", "", "Input file")
	// outputFileName := flag.String("o", "", "Output file")
	targetURL := flag.String("u", "", "Target URL")
	rulesDir := flag.String("r", "../rules", "Rules file")
	threads := flag.Int("t", 5, "Number of threads")
	debug := flag.Bool("d", false, "Enable debug logs")

	flag.Parse()

	if *inputFileName == "" && *targetURL == "" {
		fmt.Println("Target or Input file required.")
		os.Exit(1)
	}

	
	// Read yara rule files
	fmt.Printf("%s Using Rules Directory %s\n", color.BlueString("[*]"), *rulesDir)
	fmt.Println(ReadDir(*rulesDir))

	// Create yara rule compiler
	namespace := "all"
	compiler, err := yara.NewCompiler()
	if err != nil {
		panic(err)
	}

	ruleFileList, err := ReadDir(*rulesDir)
	if err != nil {
		panic(err)
	}

	for _, r := range ruleFileList {
		filePath := path.Join(*rulesDir, r)
		f ,err := os.Open(filePath)
		if err != nil {
			fmt.Printf("%s Unable to open YARA rule: %s\n", color.RedString("[!]", filePath))
			panic(err)
		}
		defer f.Close()

		err = compiler.AddFile(f, namespace)
		if err != nil {
			fmt.Printf("%s Unable to compile YARA rule: %s\n", color.RedString("[!]", filePath))
			panic(err)
		}
	}

	// Save rules into file
	rules, _ := compiler.GetRules()
	rules.Save("rulesdb")


	// If single target
	if *targetURL != "" {
		fmt.Println(targetURL)
		fmt.Println("...Not implemented...")
		return
	}

	// Otherwise, use input file
	fmt.Printf("%s Using Input file %s\n", color.BlueString("[*]"), *inputFileName)

	// Open file
	inputFile, err := os.Open(*inputFileName)
	if err != nil {
		fmt.Printf("%s Error opening input file: %s\n", color.RedString("[!]"), *inputFileName)
	}
	defer inputFile.Close()


	// Start up workers
	jobs := make(chan string)
	results := make(chan ScanResult)
	wg := new(sync.WaitGroup)

	for w := 1; w <= *threads; w++ {
		wg.Add(1)

		go func(id int, jobs <-chan string, results chan<- ScanResult) {
			defer wg.Done()


			for j := range jobs {
				url := j
				res := ScanResult{
					URL: url,
				}

				fmt.Printf("%s Scanning %s...\n", color.BlueString("[*]"), url)
				resp, err := http.Get(url)
				if err != nil {
					fmt.Printf("%s Unable to reach %s: %s\n", color.RedString("[!]"), url, err.Error())
					continue
				}
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				headerBytes := headersToBytes(resp.Header)

				var matches yara.MatchRules

				// Yara match body
				rules.ScanMem(body, 0, 120, &matches)
				res.Matches = append(res.Matches, matches)
				if *debug {
					// fmt.Println(matches)
				}

				// Yara match headers
				rules.ScanMem(headerBytes, 0, 120, &matches)
				res.Matches = append(res.Matches, matches)
				if *debug {
					fmt.Println(string(headerBytes))
				}

				results<-res

			}
		}(w, jobs, results)
	}

	// Read file line by line
	go func() {
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			line := scanner.Text()
			jobs<-line
		}
		close(jobs)
	}()

	// Wait for workers to finish and close results.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Consume results from workers
	for r := range results {
		// fmt.Println(r.Matches)
		out, err := json.Marshal(r)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(out))
	}
}


func headersToBytes(h http.Header) []byte {
	headers := ""
	for k, v := range h {
		headers = fmt.Sprintf("%s:%s\n%s",k,v[0],headers)
	}

	return []byte(headers)
}

// Read files in directory
func ReadDir(root string) ([]string, error) {
	var files []string
	fileInfo, err := ioutil.ReadDir(root)
	if err != nil {
			return files, err
	}
	for _, file := range fileInfo {
			files = append(files, file.Name())
	}
	return files, nil
}

