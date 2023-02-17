import {XYPlot, XAxis, YAxis, VerticalBarSeries, HorizontalGridLines, VerticalGridLines} from 'react-vis';
import Modal from "react-bootstrap/Modal";
import ModalTitle from "react-bootstrap/ModalTitle";
import ModalHeader from "react-bootstrap/ModalHeader";
import ModalBody from "react-bootstrap/ModalBody";
import ModalFooter from "react-bootstrap/ModalFooter";
import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import {useState} from "react";
import {setItem} from "node-forge/lib/util";

function formatPercentage(num) {
    return (num).toFixed(2) + "%";
}

const MAXBARS = 7;
function LeakageChart(props) {
    let data = [...props.data];
    let i = 1;
    while (data.length < MAXBARS){
        data.push({timestamp:" ".repeat(i), leakage:0});
        i += 1;
    }
    if (data.length > MAXBARS){
        data = data.slice(-MAXBARS);
    }
    return (
        <XYPlot
            style={{ background: "#000", color: "#fff" }}
            xType="ordinal"
            width={data.length * 100}
            height={200}
            yDomain={[0, Math.max(...data.map(v => v.leakage*100))]}
        >
            <VerticalBarSeries barWidth={0.98}  data={data.map(v => ({x: v.timestamp, y: v.leakage*100}))} fill="yellow" color="yellow" onValueClick={value => {props.setItem({x : value.x, y : formatPercentage(value.y)}); props.setInformation("Leakage"); props.setShow(true);}}/>
            <XAxis style={{ text: {stroke: 'none', fill: 'yellow', fontWeight: 600}}}  position="start" />
            <YAxis style={{ text: {stroke: 'none', fill: 'yellow', fontWeight: 600}}}
            />
        </XYPlot>
    );
}

function LatencyChart(props) {
    let data = [...props.data];
    let i = 1;
    while (data.length < MAXBARS){
        data.push({timestamp:" ".repeat(i), latency:0});
        i += 1;
    }
    if (data.length > MAXBARS){
        data = data.slice(-MAXBARS);
    }
    return (
        <XYPlot
            style={{ background: "#000", color: "#fff" }}
            xType="ordinal"
            width={data.length * 100}
            height={200}
            yDomain={[0, Math.max(...data.map(v => v.latency))]}
        >
            <VerticalGridLines />
            <HorizontalGridLines />
            <VerticalBarSeries barWidth={0.98} data={data.map(v => ({x: v.timestamp, y: v.latency}))} fill="orange" color="orange" onValueClick={value => {props.setItem({x : value.x, y : value.y}); props.setInformation("Latency"); props.setShow(true);}}/>
            <XAxis style={{ text: {stroke: 'none', fill: 'orange', fontWeight: 600}}} position="start" />
            <YAxis style={{ text: {stroke: 'none', fill: 'orange', fontWeight: 600}}} />
        </XYPlot>
    );
}

function InfoModal(props){
    let id = props.item.x.split("::")[0];
    let time = props.item.x.split("::")[1];
    return (
        <Modal show={props.show} onHide={()=> {
            props.setItem({x: "", y : 0});
            props.setShow(false);
        }}>
            <ModalHeader closeButton>
            </ModalHeader>
            <ModalBody>
                <Container>
                    <Row>
                        <Col>ID:</Col>
                        <Col>{id}</Col>
                    </Row>
                    <Row>
                        <Col>Time:</Col>
                        <Col>{time}</Col>
                    </Row>
                    <Row>
                        <Col>{props.information}:</Col>
                        <Col>{props.item.y}</Col>
                    </Row>
                </Container>
            </ModalBody>
        </Modal>);
}

export default function Plots(props){
    const [item, setItem] = useState({x: "", y : 0 });
    const [information, setInformation] = useState("");
    const [show, setShow] = useState(false);
    return (
        <div>
        <InfoModal item={item} setItem={setItem} information={information} show={show} setShow={setShow}></InfoModal>
        <Container fluid className={"justify-content-md-center"}>
            <Row>
                <Col className={"justify-content-left"}> <h3 style={{color:"yellow"}}>Leakage</h3> </Col>
                <Col className={"justify-content-left"}> <h3 style={{color:"orange"}}>Latency</h3> </Col>
            </Row>
            <Row>
                <Col className={"justify-content-md-center"}>
                    <LeakageChart data={props.leakageMeasures} setItem={setItem} setInformation={setInformation} setShow={setShow}/>
                </Col>
                <Col>
                    <LatencyChart data={props.latencyMeasures} setItem={setItem} setInformation={setInformation} setShow={setShow} />
                </Col>
            </Row>
        </Container>
        </div>
    );
}