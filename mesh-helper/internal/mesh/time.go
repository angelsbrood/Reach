// SPDX-License-Identifier: MIT

package mesh

import "time"

func nowPlusControlBudget() time.Time { return time.Now().Add(5 * time.Second) }
