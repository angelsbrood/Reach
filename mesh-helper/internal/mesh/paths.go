// SPDX-License-Identifier: MIT

package mesh

const (
	HelperVersion = "1"
	HelperPath    = "/Library/PrivilegedHelperTools/systems.reach.meshd"
	PlistPath     = "/Library/LaunchDaemons/systems.reach.meshd.plist"
	StatePath     = "/Library/Application Support/Reach Mesh"
	PrivatePath   = StatePath + "/private"
	ActivePath    = PrivatePath + "/active.json"
	PendingPath   = PrivatePath + "/pending.json"
	ApplyLockPath = PrivatePath + "/apply.lock"
	StatusPath    = StatePath + "/status.json"
	ControlPath   = "/var/run/systems.reach.meshd.sock"
)

type Paths struct {
	State   string
	Private string
	Active  string
	Pending string
	Lock    string
	Status  string
	Control string
}

func SystemPaths() Paths {
	return Paths{
		State: StatePath, Private: PrivatePath, Active: ActivePath,
		Pending: PendingPath, Lock: ApplyLockPath, Status: StatusPath,
		Control: ControlPath,
	}
}
