package version

import (
	"fmt"
	"runtime/debug"
	"sync"
)

// Version contains build and version information.
type Version struct {
	Revision string
	Version  string
	Time     string
	Dirty    bool
}

var ver = Version{
	Revision: "unknown",
	Version:  "unknown",
	Time:     "unknown",
	Dirty:    false,
}

func (v Version) String() string {
	return fmt.Sprintf(`Revision: %s
Version: %s
BuildTime: %s
Dirty: %t`, v.Revision, v.Version, v.Time, v.Dirty)
}

// Get retrieves version information from Go build info.
func Get() Version {
	sync.OnceFunc(func() {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			ver.Version = bi.Main.Version
		}
		for _, setting := range bi.Settings {
			switch setting.Key {
			case "vcs.revision":
				ver.Revision = setting.Value
			case "vcs.time":
				ver.Time = setting.Value
			case "vcs.modified":
				ver.Dirty = setting.Value == "true"
			}
		}
	})()
	return ver
}
