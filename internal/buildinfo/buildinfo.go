package buildinfo

import "runtime"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	Platform  string `json:"platform"`
}

func Current() Info {
	return Info{
		Name:      "dataminim",
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func String() string {
	info := Current()
	return info.Name + " " + info.Version + " commit=" + info.Commit + " build_date=" + info.BuildDate + " platform=" + info.Platform
}
