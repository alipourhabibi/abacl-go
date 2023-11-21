package policy

type Policy struct {
	Subject string
	Object  string
	Action  string

	Time     []Time
	Field    []string
	Filter   []string
	Location []string
}

type Time struct {
	CronExp  string
	Duration int
}
