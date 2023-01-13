package server

// //export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig/python3-embed.pc
// #cgo pkg-config: python3-embed
// #include <Python.h>
import "C"
import (
	"fmt"
	"io/ioutil"
	"log"
)

func readBytesFromFile(filepath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

/*
func testXER() {
	defer python3.Py_Finalize()
	python3.Py_Initialize()
	if !python3.Py_IsInitialized() {
		fmt.Println("Error initializing the python interpreter")
		os.Exit(1)
	}
	dir := "/home/intx/GolandProjects/pir/server"
	//dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	ret := python3.PyRun_SimpleString("import sys\nsys.path.append(\"" + dir + "\")")
	if ret != 0 {
		log.Fatalf("error appending '%s' to python sys.path", dir)
	}

	ModuleImport := python3.PyImport_ImportModule("pyasn") //new ref
	if !(ModuleImport != nil && python3.PyErr_Occurred() == nil) {
		python3.PyErr_Print()
		log.Fatal("failed to import module 'pyoutliers'")
	}
	defer ModuleImport.DecRef()
	Module := python3.PyImport_AddModule("pyasn")              //borrowed ref
	Dict := python3.PyModule_GetDict(Module)                   //borrowed ref
	decodeFunc := python3.PyDict_GetItemString(Dict, "decode") //borrowed

	input, _ := readBytesFromFile("assoc")
	inputBuf := bytes.NewBuffer(input)
	inputPyBytes := python3.PyByteArray_FromStringAndSize(inputBuf.String()) //new Ref
	args := python3.PyTuple_New(1)                                           //retval: New reference
	if args == nil {
		inputPyBytes.DecRef()
		fmt.Errorf("error creating args tuple")
		return
	}
	defer args.DecRef()
	ret = python3.PyTuple_SetItem(args, 0, inputPyBytes) //steals ref to input
	if ret != 0 {
		if python3.PyErr_Occurred() != nil {
			python3.PyErr_Print()
		}
		return
	}
	output := decodeFunc.CallObject(args) //new ref
	if !(output != nil && python3.PyErr_Occurred() == nil) {
		python3.PyErr_Print()
		fmt.Printf("error calling function")
		return
	}
	defer output.DecRef()
	goOutput, _ := convertPyObjectToIEFRecord(output)
	fmt.Println(goOutput)
}
*/

func testXER() {
	recordChan := make(chan *IEFRecord)
	server, err := NewXerServer("127.0.0.1", "1234", recordChan)
	if err != nil {
		log.Fatal(err.Error())
	}
	go func() {
		err = server.Start()
		if err != nil {
			log.Fatal(err)
		}
	}()
	log.Printf("Listening...")
	for i := 0; i < 2; i++ {
		record := <-recordChan
		if record.Assoc != nil {
			fmt.Println(record.Assoc.Supi)
		} else if record.DeAssoc != nil {
			fmt.Println(record.DeAssoc.Supi)
		}
	}
	server.Stop()
}
