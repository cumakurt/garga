package report

import "errors"

var errWriterClosed = errors.New("write report: writer is closed")
