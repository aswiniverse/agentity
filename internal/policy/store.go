package policy

// PolicyStore defines persistence operations for policies.
type PolicyStore interface {
	Insert(p *Policy) error
	Delete(id string) error
	ListAll() ([]Policy, error)
}
