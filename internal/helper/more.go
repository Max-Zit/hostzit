package helper

// registerMore adds the operations of the toolkits (WordPress, cron, SSH
// keys, mail, firewall, malware scans, backups, updates).
func (h *Helper) registerMore() {
	h.ops["wp"] = op{handle(h.wp), false}
	h.ops["wp.snapshot"] = op{handle(h.wpSnapshot), false}
	h.ops["wp.restore"] = op{handle(h.wpRestore), false}
	h.ops["site.copy"] = op{handle(h.siteCopy), false}
	h.ops["cron.apply"] = op{handle(h.cronApply), true}
	h.ops["cron.run"] = op{handle(h.cronRun), false}
	h.ops["cron.log"] = op{handle(h.cronLog), false}
	h.ops["ssh.keys"] = op{handle(h.sshKeys), false}
	h.ops["mail.relay"] = op{handle(h.mailRelay), true}
	h.ops["mail.queue"] = op{handle(h.mailQueue), false}
	h.ops["firewall"] = op{handle(h.firewall), true}
	h.ops["malware.scan"] = op{handle(h.malwareScan), false}
	for _, f := range moreOps {
		f(h)
	}
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["import.list"] = op{handle(h.importList), false}
		h.ops["import.stage"] = op{handle(h.importStage), false}
		h.ops["db.import"] = op{handle(h.dbImport), false}
		h.ops["backup.create"] = op{handle(h.backupCreate), false}
	})
}

var moreOps []func(*Helper)

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["update.check"] = op{handle(h.updateCheck), false}
		h.ops["update.install"] = op{handle(h.updateInstall), true}
	})
}
