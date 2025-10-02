package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"
)

var PublicSuffixList = MustBuildPublicSuffixList()

type Suffix struct {
	Suffix         string
	SeperatorCount int
}

func getBaseDomain(input string) string {

	var highestDetailedMatchSeperatorCount int = 0

	for i := len(PublicSuffixList) - 1; i > -1; i-- {

		if strings.HasSuffix(input, "."+PublicSuffixList[i].Suffix) && PublicSuffixList[i].SeperatorCount > highestDetailedMatchSeperatorCount {
			highestDetailedMatchSeperatorCount = PublicSuffixList[i].SeperatorCount
		}
	}

	parts := strings.Split(input, ".")

	// some people put ns records to localhost, so that's the fix
	if len(parts) <= 1 {
		return input
	}

	if highestDetailedMatchSeperatorCount == 0 {
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return strings.Join(parts[len(parts)-highestDetailedMatchSeperatorCount-1:], ".")

}

func BuildPublicSuffixList() ([]Suffix, error) {
	suffixes := []Suffix{}
	resp, err := http.Get("https://publicsuffix.org/list/public_suffix_list.dat")
	if err != nil {
		return suffixes, fmt.Errorf("failed to get public suffix list: %s", err.Error())
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return suffixes, fmt.Errorf("failed to read public suffix list: %s", err.Error())
	}

	startIndex := strings.Index(string(responseBody), "===BEGIN ICANN DOMAINS===")
	endIndex := strings.Index(string(responseBody), "===END ICANN DOMAINS===")

	for _, line := range strings.Split(string(responseBody[startIndex:endIndex]), "\n") {

		if strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "//") {
			continue
		}

		if len(line) == 0 {
			continue
		}

		suffixes = append(suffixes, Suffix{
			Suffix:         line,
			SeperatorCount: strings.Count(line, ".") + 1,
		})

	}

	fmt.Println("built public suffix list with", len(suffixes), "suffixes")

	return suffixes, nil
}

// builds the subdomain list and panics if that fails
func MustBuildPublicSuffixList() []Suffix {
	suffixes, err := BuildPublicSuffixList()
	if err != nil {
		panic(err)
	}

	return suffixes
}
