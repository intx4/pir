import { useNavigate } from "react-router-dom";
import { useState, useEffect,useRef} from "react";
import useWebSocket, { ReadyState } from 'react-use-websocket';
import {Event, Capture, Association} from "./Events";
import CapturesComp from "./Captures";
import AssociationsComp from "./Associations";
//BootStrap react imports

import Container from "react-bootstrap/Container";
import Button from "react-bootstrap/Button";
import Nav from "./Nav";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import Modal from "react-bootstrap/Modal";
import ModalTitle from "react-bootstrap/ModalTitle";
import ModalHeader from "react-bootstrap/ModalHeader";
import ModalBody from "react-bootstrap/ModalBody";
import ModalFooter from "react-bootstrap/ModalFooter";
import Form from 'react-bootstrap/Form';
import RangeSlider from 'react-bootstrap-range-slider';
import "bootstrap/dist/css/bootstrap.min.css";
import Plots from "./Plots";
const axios = require("axios").default;

function ResolveModal(props){
  console.log("modal", props);
  const keys = Array.from(props.items).map(([key, value]) => ({
    key,
  }));
  console.log(keys.length)
  if (keys.length === 0){
    return(
    <Modal show={props.show} onHide={()=> {
      props.setLeakage(0);
      props.setResolveAll(false);
      props.setShow(false);
    }}>
      <ModalHeader closeButton>
      </ModalHeader>
      <ModalBody><div style={{textAlign:"center"}}>No data!</div></ModalBody>
    </Modal>)
  }
  if (props.isResolvingAll === true && props.resolveAll === false){
    //already got the prompt to resolve all
    return (
        <Modal show={props.show} onHide={()=> {
          props.setLeakage(0);
          props.setResolveAll(false);
          props.setShow(false);
        }}>
          <ModalHeader closeButton>
          </ModalHeader>
          <ModalBody>
            <div>Set Leakage</div>
          </ModalBody>
          <ModalFooter>
            <Container>
              <Row>
                <Col>
                  <Form.Label>Leakage</Form.Label>
                  <RangeSlider value={props.leakage} variant="warning" step={1} min={0} max={2} onChange={(e)=>{
                    props.handleLeakageChange(e.target.value);
                    props.setLeakage(e.target.value);
                  }}></RangeSlider>
                </Col>
                <Col>
                  <Form.Check
                    type="switch"
                    label="Resolve by SUCI"
                    variant={"warning"}
                    checked={props.bySUCI}
                    onChange={e => {props.handleTypeChange(e.target.checked);props.setBySUCI(e.target.checked)}}
                /></Col>
                <Col>
                  <Button variant="success" onClick={() => {
                    props.setShow(false);}}>Confirm</Button>
                </Col>
              </Row>
            </Container>
          </ModalFooter>
        </Modal>
    );
  }
  return(
      <Modal show={props.show} onHide={()=> {
        props.setLeakage(0);
        props.setResolveAll(false);
        props.setShow(false);
      }}>
        <ModalHeader closeButton>
        </ModalHeader>
        <ModalBody>
          {props.resolveAll === true ? (<div>Resolve All Captures</div>)
          : props.items.has(props.id) === true ? (<Container>
                  <Row>
                    <Col>SUCI</Col>
                    <Col>TMSI</Col>
                    <Col>Timestamp</Col>
                  </Row>
                  <Row>
                    <Col>{(props.items.get(props.id)).suci}</Col>
                    <Col>{(props.items.get(props.id)).guti}</Col>
                    <Col>{(props.items.get(props.id)).timestamp}</Col>
                  </Row>
                </Container>) : (<div></div>)
              }
        </ModalBody>
        <ModalFooter>
          <Container>
            <Row>
              <Col>
                <Form.Label>Leakage</Form.Label>
                <RangeSlider value={props.leakage} variant="warning" step={1} min={0} max={2} onChange={(e)=>{
                  props.handleLeakageChange(e.target.value);
                  props.setLeakage(e.target.value);
                }}></RangeSlider>
              </Col>
              <Col><Form.Check
                  type="switch"
                  label="Resolve by SUCI"
                  variant={"warning"}
                  checked={props.bySUCI}
                  onChange={e => {props.handleTypeChange(e.target.checked); props.setBySUCI(e.target.checked)}}
              /></Col>
              <Col>
                <Button variant="danger" onClick={() => {
                  props.handleResolve(); //will set resolveAll to false
                  props.setShow(false);}}>RESOLVE</Button>
              </Col>
            </Row>
          </Container>
          </ModalFooter>
      </Modal>
  );
}

export default function Home(props) {
  let addr = props.addr;
  const [captures, setCaptures] = useState(new Map()); //id -> capture
  const [loadingCaptures, setLoadingCaptures] = useState(new Map()); //id -> capture
  const [associations, setAssociations] = useState(new Map()); //id -> association
  const [latencyMeasures, setLatencyMeasures] = useState([]);
  const [leakageMeasures, setLeakageMeasures] = useState([]);
  const [resolveModalShow, setResolveModelShow] = useState(false);
  const [clickedCaptureId, setClickedCaptureId] = useState(-1);
  const [leakage, setLeakage] = useState(0);
  const [bySUCI, setBySUCI] = useState(false); //resolve by SUCI or guti
  const [resolveAll, setResolveAll] = useState(false);
  const [isResolvingAll, setIsResolvingAll] = useState(false);
  const ws = useRef(null); //on .current change, ws will still be treated as same object not triggering re-render

  let handleMessage = (Obj) => {
    let evt = Event.fromJSON(Obj);
    if (evt.getType() === "capture"){
      console.log("Capture event");
      let capture = Capture.fromJSON(Obj);
      setCaptures(prevCaptures => new Map(prevCaptures).set(capture.id, capture));
    }else if (evt.getType() === "association"){
      console.log("Association event");
      let association = Association.fromJSON(Obj);
        if (association.error !== ""){
          console.log("Loading")
          console.log(loadingCaptures)
          console.log("error in assoc")
          window.alert(association.error)
          if (loadingCaptures.has(association.id)) {
            console.log("deleting from loading")
            console.log(association.id)
            setLoadingCaptures(prevCaptures => {
              let newCaptures = new Map(prevCaptures);
              newCaptures.delete(association.id);
              console.log("loading captures: ", newCaptures)
              if (Array.from(newCaptures).map(([key, value]) => ({
                key,
              })).length === 0){
                console.log("Finished resolving all")
                setIsResolvingAll(false);
              }
              return newCaptures});
          }
          return
        }
        if (captures.has(association.id)) {
          setCaptures(prevCaptures => {let newCaptures = new Map(prevCaptures); newCaptures.delete(association.id); return newCaptures});
        }
        if (loadingCaptures.has(association.id)) {
          setLoadingCaptures(prevCaptures => {
            let newCaptures = new Map(prevCaptures);
            newCaptures.delete(association.id);
            if (Array.from(loadingCaptures).map(([key, value]) => ({
              key,
            })).length === 0){
              setIsResolvingAll(false);
            }
            return newCaptures});
        }
        setAssociations(prevAssociations => new Map(prevAssociations).set(association.id, association));
        const currentTime = new Date();
        const hours = currentTime.getHours();
        const minutes = currentTime.getMinutes();
        const seconds = currentTime.getSeconds();

        const formattedTime = `${hours}:${minutes}:${seconds}`;
        setLatencyMeasures(prevLatency => {
          let newLatency = [];
          newLatency.push(...prevLatency);
          let prefix = prevLatency.length.toString() + "::"
          newLatency.push({timestamp: prefix+formattedTime, latency:association.latency});
          return newLatency;
        });
        setLeakageMeasures(prevLeakage => {
          let newLeakage = [];
          newLeakage.push(...prevLeakage);
          let prefix = prevLeakage.length.toString() + "::"
          newLeakage.push({timestamp: prefix+formattedTime, leakage:association.leakage});
          return newLeakage;
        });
    }
  }
  useEffect(() => {
    try {
      ws.current = new WebSocket("ws://"+addr+":8484/api/subscribe");
      ws.current.onopen = () => console.log("WebSocket opened");
      ws.current.onclose = () => console.log("WebSocket closed");

      const wsCurrent = ws.current;

      return () => {
        wsCurrent.close();
      };
    }
    catch (error) {
      console.log(error);
      window.alert("Could not establish connection to Backend. Try refreshing the page...")
    }
  },[]);

  useEffect(() => {
    if (!ws.current) return;
    ws.current.onmessage = e => {
      const message = JSON.parse(e.data);
      console.log("Event from backend:", message);
      handleMessage(message)
    };
  },[captures, associations, loadingCaptures, resolveAll, isResolvingAll, latencyMeasures, leakageMeasures])

  function ChangeLeakage(leakage){
    let obj = {
      id: parseInt(-1),
      infoLeakage: {leakage:parseInt(leakage)},
    };
    console.log("Change leakage")
    console.log(obj)
    ws.current.send(JSON.stringify(obj))
  }

  function ChangeType(bySUCI){
    let obj = {
      id: parseInt(-1),
      infoType: {type: bySUCI === true ? "SUCI" : "TMSI"},
    };
    console.log("Change type")
    console.log(obj)
    ws.current.send(JSON.stringify(obj))
  }
  async function Resolve() {
    console.log("Resolve");
    let ids = [];
    if (resolveAll === true) {
      setIsResolvingAll(true);
      Array.from(captures).map(([key, value]) => {
        ids.push(key)
      });
    } else {
      ids.push(clickedCaptureId);
    }
    console.log(ids)

    for (const id of ids){
      console.log("Adding to loading")
      console.log(id)
      setLoadingCaptures(prevState => {
        let newState = new Map(prevState);
        newState.set(id, true);
        return newState;
      })
    }
    setResolveAll(false);
    setClickedCaptureId(-1);
    let delay = 500; // Set the delay time in milliseconds
    for (const id of ids) {
      let obj = {
        id: parseInt(id),
        leakage: parseInt(leakage),
        type: bySUCI === true ? "SUCI" : "TMSI"
      };
      console.log("Resolve request")
      console.log(obj)
      setLoadingCaptures(prevState => {
        let newState = new Map(prevState);
        newState.set(id, true);
        return newState;
      })
      ws.current.send(JSON.stringify(obj))
      await new Promise(resolve => setTimeout(resolve, delay)); // Wait for the specified delay time
    }
  }

  return (
      <div className="Dashboard">
      <ResolveModal show={resolveModalShow} setShow={setResolveModelShow}
                    leakage={leakage} setLeakage={setLeakage}
                    bySUCI={bySUCI} setBySUCI={setBySUCI}
                    items={captures}
                    loadingItems={loadingCaptures} setLoadingItems={setLoadingCaptures}
                    id={clickedCaptureId}
                    resolveAll={resolveAll} setResolveAll={setResolveAll}
                    isResolvingAll={isResolvingAll}
                    handleLeakageChange={ChangeLeakage}
                    handleTypeChange={ChangeType}
                    handleResolve={Resolve}></ResolveModal>
      <Nav></Nav>
        <Plots latencyMeasures={latencyMeasures} leakageMeasures={leakageMeasures}></Plots>
        <Container fluid={true}>
          <Row>
            <Col xl={5} md={5} xd={5} style={{ text :{fill: "white"} ,color:"white"}}>
              <CapturesComp items={captures}
                            setResolveModalShow={setResolveModelShow}
                            loadingCaptures={loadingCaptures}
                            setClickedCaptureId={setClickedCaptureId} setResolveAll={setResolveAll}
                            isResolvingAll={isResolvingAll} setIsResolvingAll={setIsResolvingAll}/>
            </Col>
            <Col xl={7} md={7} xd={7} style={{ text :{fill: "white"} ,color:"white"}}>
              <AssociationsComp items={associations}/>
            </Col>
          </Row>
        </Container>
      </div>
  );
}
