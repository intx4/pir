package utils

import (
	"github.com/sirupsen/logrus"
	"os"
)

var Logger = &logrus.Logger{
	Out:          nil,
	Hooks:        nil,
	Formatter:    nil,
	ReportCaller: false,
	Level:        logrus.DebugLevel,
	ExitFunc:     nil,
	BufferPool:   nil,
}

func LogInit() {
	var logFile, err = os.OpenFile(os.ExpandEnv("$HOME/pir/var/log/pir.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	Logger.Out = logFile
}
