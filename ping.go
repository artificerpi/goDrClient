package main

import (
	"log"
	"os/exec"
	"regexp"
	"strings"
)

var LATENCY_PATTERN *regexp.Regexp = regexp.MustCompile(`=(.*) *ms`)

// This works for both mac and linux output, not sure if for windows too...
func parseResults(cmd *exec.Cmd, address string, pattern *regexp.Regexp) bool {
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("event='ping_cmd_error' addresss='%s' error='%s'\n", address, err)
	}
	if len(output) > 0 {
		for _, line := range strings.Split(string(output), "\n") {
			if matches := pattern.FindStringSubmatch(line); matches != nil && len(matches) >= 2 {
				log.Printf("event='ping_latency'  addresss='%s' latency_ms='%s'\n", address, strings.TrimSpace(matches[1]))
				return true
			}
		}
	}
	// guess we never found a ping latency in our response data
	log.Printf("event='missed_ping_latency' addresss='%s'\n", address)
	return false
}
