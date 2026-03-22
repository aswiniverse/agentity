package audit

// AuditStore defines persistence operations for audit log entries.
type AuditStore interface {
	Insert(entry *AuditEntry) error
	List(filter AuditFilter) ([]AuditEntry, error)
	Count() (int, error)
}
