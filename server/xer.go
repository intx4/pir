package server

// //BEFORE RUNNING:
// //export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig/python3-embed.pc
// //export PYASN_DIR = dir of pyasn
// #cgo pkg-config: python3-embed
// #include <Python.h>
import "C"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/christian-korneck/go-python3"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
	"os"
	"pir/utils"
)

type IEFRecord struct {
	Assoc   *IEFAssociationRecord   `json:"assoc,omitempty"`
	DeAssoc *IEFDeassociationRecord `json:"deassoc,omitempty"`
}

type IEFAssociationRecord struct {
	Supi      string            `json:"supi,omitempty"`
	FiveGGUTI string            `json:"fivegguti,omitempty"`
	Timestmp  string            `json:"timestmp,omitempty"`
	Tai       string            `json:"tai,omitempty"`
	Ncgi      map[string]string `json:"ncgi,omitempty"`
	NcgiTime  string            `json:"ncgi_time,omitempty"`
	Suci      string            `json:"suci,omitempty"`
	Pei       string            `json:"pei,omitempty"`
	ListOfTai []string          `json:"list_of_tai,omitempty"`
}

type IEFDeassociationRecord struct {
	Supi      string            `json:"supi,omitempty"`
	Suci      string            `json:"suci,omitempty"`
	FiveGGUTI string            `json:"fivegguti,omitempty"`
	Timestmp  string            `json:"timestmp,omitempty"`
	Ncgi      map[string]string `json:"ncgi,omitempty"`
	NcgiTime  string            `json:"ncgi_time,omitempty"`
}

func convertPyObjectToIEFRecord(pyObject *python3.PyObject) (*IEFRecord, error) {
	iefRecord := &IEFRecord{}
	var assoc *IEFAssociationRecord
	var deassoc *IEFDeassociationRecord
	var err error
	isAssoc := python3.PyLong_AsLong(pyObject.GetAttrString("isAssoc"))        //new
	decodingError := python3.PyBytes_AsString(pyObject.GetAttrString("error")) //new
	if decodingError != "None" {
		utils.Logger.WithFields(logrus.Fields{"service": "XER", "error": decodingError}).Error("Error")
		fmt.Println("ERROR: ", decodingError)
		return nil, errors.New(decodingError)
	}
	if isAssoc == 1 {
		assocPyObject := pyObject.GetAttrString("assoc")
		defer assocPyObject.DecRef()
		if assocPyObject == nil {
			assoc = nil
		} else {
			assoc, err = convertPyObjectToIEFAssociationRecord(assocPyObject)
			if err != nil {
				return nil, err
			}
		}
		utils.Logger.WithFields(logrus.Fields{"service": "XER", "association": assoc}).Info("IEFRecord:")
		iefRecord.Assoc = assoc
	} else if isAssoc == 0 {
		deassocPyObject := pyObject.GetAttrString("deassoc")
		defer deassocPyObject.DecRef()
		if deassocPyObject == nil {
			deassoc = nil
		} else {
			deassoc, err = convertPyObjectToIEFDeassociationRecord(deassocPyObject)
			if err != nil {
				return nil, err
			}
		}
		utils.Logger.WithFields(logrus.Fields{"service": "XER", "association": deassoc}).Info("IEFRecord:")
		iefRecord.DeAssoc = deassoc
	}
	return iefRecord, nil
}

func convertPyObjectToIEFAssociationRecord(pyObject *python3.PyObject) (*IEFAssociationRecord, error) {
	iefAssociationRecord := &IEFAssociationRecord{}
	iefAssociationRecord.Supi = python3.PyBytes_AsString(pyObject.GetAttrString("supi"))
	iefAssociationRecord.FiveGGUTI = python3.PyBytes_AsString(pyObject.GetAttrString("fivegguti"))
	iefAssociationRecord.Timestmp = python3.PyBytes_AsString(pyObject.GetAttrString("timestmp"))
	iefAssociationRecord.Tai = python3.PyBytes_AsString(pyObject.GetAttrString("tai"))

	ncgiPyObject := pyObject.GetAttrString("ncgi")
	ncgi := make(map[string]string)
	ncgi["pLMNID"] = python3.PyBytes_AsString(python3.PyDict_GetItemString(ncgiPyObject, "pLMNID"))
	ncgi["nCI"] = python3.PyBytes_AsString(python3.PyDict_GetItemString(ncgiPyObject, "nCI"))
	iefAssociationRecord.Ncgi = ncgi
	ncgiPyObject.DecRef()

	iefAssociationRecord.NcgiTime = python3.PyBytes_AsString(pyObject.GetAttrString("ncgi_time"))
	iefAssociationRecord.Suci = python3.PyBytes_AsString(pyObject.GetAttrString("suci"))
	iefAssociationRecord.Pei = python3.PyBytes_AsString(pyObject.GetAttrString("pei"))
	listOfTaiPyObject := pyObject.GetAttrString("list_of_tai")
	listOfTai := make([]string, 0)
	for i := 0; i < python3.PyList_Size(listOfTaiPyObject); i++ {
		item := python3.PyBytes_AsString(python3.PyList_GetItem(listOfTaiPyObject, i))
		listOfTai = append(listOfTai, item)
	}
	listOfTaiPyObject.DecRef()
	iefAssociationRecord.ListOfTai = listOfTai
	return iefAssociationRecord, nil
}

func convertPyObjectToIEFDeassociationRecord(pyObject *python3.PyObject) (*IEFDeassociationRecord, error) {
	iefDeassociationRecord := &IEFDeassociationRecord{}
	iefDeassociationRecord.Supi = python3.PyBytes_AsString(pyObject.GetAttrString("supi"))
	iefDeassociationRecord.FiveGGUTI = python3.PyBytes_AsString(pyObject.GetAttrString("fivegguti"))
	iefDeassociationRecord.Timestmp = python3.PyBytes_AsString(pyObject.GetAttrString("timestmp"))
	iefDeassociationRecord.Suci = python3.PyBytes_AsString(pyObject.GetAttrString("suci"))
	ncgiPyObject := pyObject.GetAttrString("ncgi")
	ncgi := make(map[string]string)
	ncgi["pLMNID"] = python3.PyBytes_AsString(python3.PyDict_GetItemString(ncgiPyObject, "pLMNID"))
	ncgi["nCI"] = python3.PyBytes_AsString(python3.PyDict_GetItemString(ncgiPyObject, "nCI"))
	iefDeassociationRecord.Ncgi = ncgi
	ncgiPyObject.DecRef()

	iefDeassociationRecord.NcgiTime = python3.PyBytes_AsString(pyObject.GetAttrString("ncgi_time"))
	return iefDeassociationRecord, nil
}

type XerHandler struct {
	Decoder    *python3.PyObject
	recordChan chan *IEFRecord
}
type XerServer struct {
	Addr     string
	Port     string
	handler  *XerHandler
	shutDown chan struct{}
}

func NewXerServer(addr string, port string, recordChan chan *IEFRecord) (*XerServer, error) {
	python3.Py_Initialize()
	if !python3.Py_IsInitialized() {
		return nil, errors.New("Error initializing Python interpreter")
	}

	//dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	dir := os.Getenv("PYASN_DIR")
	ret := python3.PyRun_SimpleString("import sys\nsys.path.append(\"" + dir + "\")")
	if ret != 0 {
		python3.PyErr_Print()
		return nil, errors.New(fmt.Sprintf("error appending PYASN_DIR env variable to python sys.path"))
	}

	ModuleImport := python3.PyImport_ImportModule("pyasn") //new ref
	if !(ModuleImport != nil && python3.PyErr_Occurred() == nil) {
		python3.PyErr_Print()
		return nil, errors.New("Error inporting module pyasn")
	}
	defer ModuleImport.DecRef()
	Module := python3.PyImport_AddModule("pyasn")              //borrowed ref
	Dict := python3.PyModule_GetDict(Module)                   //borrowed ref
	decodeFunc := python3.PyDict_GetItemString(Dict, "decode") //borrowed
	decodeFunc.IncRef()

	return &XerServer{
		Addr: addr,
		Port: port,
		handler: &XerHandler{
			Decoder:    decodeFunc,
			recordChan: recordChan,
		},
		shutDown: make(chan struct{}),
	}, nil
}

func (xs *XerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	switch r.Method {
	case "GET":
		fmt.Fprintf(w, "405 - GET not allowed")
	case "POST":
		buff := make([]byte, r.ContentLength)
		r.Body.Read(buff)
		inputBuf := bytes.NewBuffer(buff)
		utils.Logger.WithFields(logrus.Fields{"service": "XER", "body": inputBuf.String()}).Info("POST request")
		inputPyBytes := python3.PyBytes_FromString(inputBuf.String()) //new Ref
		args := python3.PyTuple_New(1)                                //retval: New reference
		if args == nil {
			inputPyBytes.DecRef()
			fmt.Errorf("error creating args tuple")
			utils.Logger.WithFields(logrus.Fields{"service": "XER", "error": "error creating pyTuple for pyasn.decode call"}).Error("Error")
			return
		}
		defer args.DecRef()
		ret := python3.PyTuple_SetItem(args, 0, inputPyBytes) //steals ref to input
		if ret != 0 {
			if python3.PyErr_Occurred() != nil {
				python3.PyErr_Print()
				utils.Logger.WithFields(logrus.Fields{"service": "XER", "error": "error setting pyTuple for pyasn.decode call"}).Error("Error")
			}
			return
		}
		output := xs.Decoder.CallObject(args) //new ref
		if !(output != nil && python3.PyErr_Occurred() == nil) {
			python3.PyErr_Print()
			fmt.Printf("error calling function")
			utils.Logger.WithFields(logrus.Fields{"service": "XER", "error": "error during pyasn.decode call"}).Error("Error")
			return
		}
		defer output.DecRef()
		goOutput, err := convertPyObjectToIEFRecord(output)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "200 Ok")
		utils.Logger.WithFields(logrus.Fields{"service": "XER"}).Error("Sending POST response 200 OK")
		xs.recordChan <- goOutput
	default:
		utils.Logger.WithFields(logrus.Fields{"service": "XER", "error": "HTTP method not supported"}).Error("Error")
		fmt.Fprintf(w, "405 - only POST methods are supported.")
	}
}

// Blocking
func (xs *XerServer) Start() error {
	server := http.Server{Addr: xs.Addr + ":" + xs.Port, Handler: xs.handler}
	go func() {
		<-xs.shutDown
		if err := server.Shutdown(context.Background()); err != nil {
			log.Fatalf("Server Shutdown Failed:%+v", err)
		}
		log.Print("Server Exited Properly")
	}()
	utils.Logger.WithFields(logrus.Fields{"service": "XER", "addr": xs.Addr, "port": xs.Port}).Info("Server started")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		utils.Logger.WithFields(logrus.Fields{"service": "XER", "error": err.Error()}).Info("Error")
		return err
	}
	return nil
}

func (xs *XerServer) Stop() {
	close(xs.shutDown)
}
