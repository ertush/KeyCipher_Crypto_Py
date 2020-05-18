package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
)

// Over-all Command
var cmd = &cobra.Command{
	Use:   "base64",
	Short: "Usage : base64 [mode] [inFilePath] [outFilePath]",
	Run: func(c *cobra.Command, args []string) {
		if len(args) < 2 {
			fmt.Println("[!] Must provide both input and output file paths")
		}
	},
}

// File Encode Sub-Command
var encodeSubCmd = &cobra.Command{
	Use:   "encode",
	Short: "File to base64 encode",
	Run: func(cmd *cobra.Command, args []string) {
		if args[0] == "" {
			log.Fatalln("[!] Input File missing")
		}

		if args[1] == "" {
			log.Fatalln("[!] Output File missing")
		}

		if len(args) <= 2 {

			fmt.Println("[+] Starting file encoding ...")

			inDir := string(args[0])
			outDir := string(args[1])

			content, err := ioutil.ReadFile(inDir)

			if err != nil {
				log.Fatal(err)
			}

			// Decoding file
			encoded := base64.StdEncoding.EncodeToString(content)

			if err := ioutil.WriteFile(outDir, []byte(encoded), 0666); err != nil {
				log.Fatal(err)
			}

			fmt.Println("[+] Done encoding file")

		}

	},
}

// File Decode Sub-Command
var decodeSubCmd = &cobra.Command{
	Use:   "decode",
	Short: "File to base64 decode",
	Run: func(cmd *cobra.Command, args []string) {

		if args[0] == "" {
			log.Fatalln("[!] Input File missing")
		}

		if args[1] == "" {
			log.Fatalln("[!] Output File missing")
		}

		if len(args) <= 2 {

			fmt.Println("[+] Starting file decoding ...")

			inDir := string(args[0])
			outDir := string(args[1])

			content, err := ioutil.ReadFile(inDir)
			if err != nil {
				log.Fatal(err)
			}

			// File Decoding
			decoded, err := base64.StdEncoding.DecodeString(string(content))
			if err != nil {
				log.Fatal(err)
			}

			if err := ioutil.WriteFile(outDir, decoded, 0666); err != nil {
				log.Fatal(err)
			}

			fmt.Println("[+] Done decoding file")
		}
	},
}

//String Encode Sub-Command
var encodeString = &cobra.Command{
	Use:   "encode-string",
	Short: "Encode a string",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalln("[!] Must provide a string to encode")
		}

		if args[0] != "" {
			content := base64.StdEncoding.EncodeToString([]byte(args[0]))
			fmt.Println(content)
		}
	},
}

//String Decode Sub-Command
var decodeString = &cobra.Command{
	Use:   "decode-string",
	Short: "Decode a string",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalln("[!] Must provide a string to decode")
		}

		if args[0] != "" {
			data, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(string(data))

		}
	},
}

var inFilePath string

func main() {

	encodeSubCmd.PersistentFlags().StringVarP(&inFilePath, "encode", "e", "", "Path File to Encode")
	decodeSubCmd.PersistentFlags().StringVarP(&inFilePath, "decode", "d", "", "Path File to Decode")

	encodeString.PersistentFlags().StringVarP(&inFilePath, "encode-string", "s", "", "String to be Encoded")
	encodeString.PersistentFlags().StringVarP(&inFilePath, "decode-string", "t", "", "String to be Decoded")

	cmd.AddCommand(encodeSubCmd)
	cmd.AddCommand(decodeSubCmd)
	cmd.AddCommand(encodeString)
	cmd.AddCommand(decodeString)

	err := cmd.Execute()
	if err != nil {
		log.Fatalln("[!] Unable to execute base64.exe")
	}

}
