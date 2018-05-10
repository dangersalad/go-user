package user

type logger interface {
	Debug(...interface{})
	Printf(string, ...interface{})
}

var lg logger

// SetLogger sets a logger on the package that will print messages
func SetLogger(l logger) {
	lg = l
}

func debug(a ...interface{}) {
	if lg == nil {
		return
	}
	lg.Debug(a...)
}

func logf(f string, a ...interface{}) {
	if lg == nil {
		return
	}
	lg.Printf(f, a...)
}
