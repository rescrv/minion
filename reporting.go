package minion

import (
	"fmt"
	"strings"
)

type BuildReport struct {
	BuildInfo
	Processes []string
	Reports   map[string]ProcessReport
}

func tabIndent(in string) string {
	out := ""
	for _, s := range strings.Split(in, "\n") {
		out += "\t" + s + "\n"
	}
	out = strings.TrimRight(out, " \t\n\r")
	return out + "\n"
}

func (br *BuildReport) ReportInfo() string {
	r := ""
	r += fmt.Sprintf("Target: %s\n", br.Target)
	r += fmt.Sprintf("Name:   %s\n", br.Name)
	r += fmt.Sprintf("Time:   %s\n", br.Time.Format("2006-01-02T15:04:05Z"))
	return r
}

func (br *BuildReport) ReportShort() string {
	r := br.ReportInfo()
	pad := 10
	for _, proc := range br.Processes {
		if len(proc) > pad {
			pad = len(proc)
		}
	}
	for _, proc := range br.Processes {
		rep, ok := br.Reports[proc]
		if !ok {
			r += fmt.Sprintf("%s SKIPPED\n", proc)
			continue
		}
		for len(proc) < pad {
			proc += " "
		}
		r += fmt.Sprintf("%s %s", proc, rep.Status)
		if rep.Released {
			r += " RELEASED"
		} else if rep.Cached {
			r += " CACHED"
		}
		r += "\n"
	}
	return r
}

func (br *BuildReport) ReportLong() string {
	r := br.ReportInfo()
	pad := 10
	for _, proc := range br.Processes {
		if len(proc) > pad {
			pad = len(proc)
		}
	}
	for _, proc := range br.Processes {
		rep, ok := br.Reports[proc]
		if !ok {
			r += fmt.Sprintf("%s SKIPPED\n", proc)
			continue
		}
		for len(proc) < pad {
			proc += " "
		}
		r += fmt.Sprintf("%s %s", proc, rep.Status)
		if rep.Released {
			r += " RELEASED"
		} else if rep.Cached {
			r += " CACHED"
		}
		r += "\n"
		if rep.Status != SUCCESS {
			r += tabIndent(rep.StatusMsg)
		}
		if rep.Status == FAILED {
			r += tabIndent(rep.Log)
		}
	}
	return r
}
