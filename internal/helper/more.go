package helper

// registerMore adds the operations of the toolkits (WordPress, cron, SSH
// keys, firewall, backups, updates).
func (h *Helper) registerMore() {
	h.ops["wp"] = op{handle(h.wp), false}
	h.ops["wp.snapshot"] = op{handle(h.wpSnapshot), false}
	h.ops["wp.restore"] = op{handle(h.wpRestore), false}
}
