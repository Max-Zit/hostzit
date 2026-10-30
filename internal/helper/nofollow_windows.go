package helper

import "os"

const openNoFollow = 0

const noFollowFile = 0

// fileOwner: Windows has no uids (the helper runs on Linux only; tests).
func fileOwner(os.FileInfo) (int, bool) { return 0, false }
