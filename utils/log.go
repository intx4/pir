// Package implements utilities function
package utils

import (
	"github.com/sirupsen/logrus"
	"os"
)

var MAXLEN = 1 * 1024 //1 KB

var Logger = &logrus.Logger{
	Out:       os.Stdout,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.DebugLevel,
}

func LogInit() {
	var logFile, err = os.OpenFile(os.Getenv("PIR_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	Logger.Out = logFile
}
