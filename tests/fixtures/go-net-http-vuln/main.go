// Deliberately vulnerable net/http + exec fixture for Plan F multilang
// coverage tests. The /run handler reads ?cmd= from the URL query and
// passes it directly to exec.Command via /bin/sh -c — an intentional
// CWE-78 (OS command injection) sink reachable from an HTTP source.
// Static_hunter / gosec / semgrep should flag the source -> sink dataflow.

package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func runHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// DELIBERATE COMMAND INJECTION SINK (CWE-78): user-controlled `cmd` is
	// passed verbatim to /bin/sh -c.
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, string(out))
}

func main() {
	http.HandleFunc("/run", runHandler)
	_ = http.ListenAndServe(":3000", nil)
}
