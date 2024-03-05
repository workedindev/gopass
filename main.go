package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
)

const (
	MinLength      = 16
	LowercaseRange = "a-z"
	UppercaseRange = "A-Z"
	NumericRange   = "0-9"
)

var alphaEnabled, numericEnabled, symbolsEnabled bool

func buildAlphabet(deny *string) ([]byte, string) {
	validAlphabet := make([]byte, 0, 75)
	alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numeric := "0123456789"
	symbols := "#?!@$ %^&*-"

	if alphaEnabled {
		for _, char := range *deny {
			alpha = strings.ReplaceAll(alpha, string(char), "")
		}
		validAlphabet = append(validAlphabet, alpha...)
	}
	if numericEnabled {
		for _, char := range *deny {
			numeric = strings.ReplaceAll(string(numeric), string(char), "")
		}
		validAlphabet = append(validAlphabet, numeric...)
	}
	if symbolsEnabled {
		for _, char := range *deny {
			symbols = strings.ReplaceAll(string(symbols), string(char), "")
		}
		validAlphabet = append(validAlphabet, symbols...)
	} else {
		symbols = ""
	}
	return []byte(validAlphabet), string(symbols)
}

func buildPassword(length int, alphabet []byte, regexTests *map[string]*regexp.Regexp) string {
	generatedPassword := ""
	passes := 0

	for passes < len(*regexTests) {
		generatedPassword = ""
		for i := 0; i < length; i++ {
			generatedPassword += string(alphabet[rand.IntN(len(alphabet))])
		}
		for regTestName, regTest := range *regexTests {
			if !regTest.MatchString(generatedPassword) {
				fmt.Printf("failed %s test\n", regTestName)
				passes = 0
				break
			}
			passes += 1
		}
	}
	return generatedPassword
}

func generatePassword(length int, deny *string) string {
	alphabet, symbols := buildAlphabet(deny)

	regexTests := make(map[string]*regexp.Regexp)

	fullValidRegex := ""
	if alphaEnabled {
		fullValidRegex += LowercaseRange + UppercaseRange

		regexTests["lower"] = regexp.MustCompile(
			fmt.Sprintf(".*[%s].*", LowercaseRange))

		regexTests["upper"] = regexp.MustCompile(
			fmt.Sprintf(".*[%s].*", UppercaseRange))
	}
	if numericEnabled {
		fullValidRegex += NumericRange

		regexTests["numeric"] = regexp.MustCompile(
			fmt.Sprintf(".*[%s].*", NumericRange))
	}
	if symbolsEnabled {
		fullValidRegex += symbols

		regexTests["symbols"] = regexp.MustCompile(
			fmt.Sprintf(".*[%s].*", symbols))
	}
	return buildPassword(length, alphabet, &regexTests)
}

func main() {
	length := flag.Int("l", MinLength, "length for the password")
	flag.BoolVar(&alphaEnabled, "a", false, "flag to enable using letters from the alphabet")
	flag.BoolVar(&numericEnabled, "n", false, "flag to enable using numbers")
	flag.BoolVar(&symbolsEnabled, "s", false, "flag to enable using symbols")
	deny := flag.String("d", "", "list of explicitly denied characters")
	flag.Parse()

	fmt.Printf("%s", generatePassword(*length, deny))
}
