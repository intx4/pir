import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import Button from 'react-bootstrap/Button';
import Spinner from 'react-bootstrap/Spinner';
import {Event, Captures} from "./Events";

export default function CapturesComp (props) {
    function handleButtonClick(){
        if (props.isResolvingAll === false) {
            props.setResolveAll(true);
        }
        props.setResolveModalShow(true);
    }
    function handleRowClick(id) {
        props.setClickedCaptureId(id);
        props.setResolveModalShow(true);
        console.log("Clicked")
        console.log(id)
        console.log("loading")
        console.log(props.loadingCaptures)
        console.log("loading all, ", props.isResolvingAll)
    }
    console.log("Capture list")
    const items = Array.from(props.items).map(([key, value]) => ({
        value,
    }));
    console.log(items);
    console.log("Loading for captures");
    console.log(props.loadingCaptures)
    if (props.isResolvingAll === true && Array.from(props.loadingCaptures).map(([key, value]) => ({
            key,
        })).length === 0){
        props.setIsResolvingAll(false);
    }


    return (
        <Container fluid={true}>
            <Row>
                <Col xs={8} md={8} xl={8}> <h1>Captures</h1></Col>
                <Col xs={3} md={3} xl={3} as={"div"} style={{margin:"1%"}}>
                    {props.isResolvingAll === false ? (<Button variant="danger" onClick={()=>handleButtonClick()}>Resolve All</Button>) : (<Button variant="info" onClick={()=>handleButtonClick()}>Set Leakage</Button>)}
                </Col>
            </Row>
            <Row className={"border-white"}>
                <Col ><h2>SUCI</h2></Col>
                <Col ><h2>TMSI</h2></Col>
                <Col><h2>Time</h2></Col>
            </Row>
            <div style={{
                overflow: "auto",
                width: "100%",
                height: 300,}}>
            {items.map( item => (
                    props.loadingCaptures.has(item.value.id) === false ? (
                            <div className="capture_item" key={item.value.id} onClick={() => handleRowClick(item.value.id)}>
                                <Row>
                                    <Col  style={{ borderRight: '1px solid #ddd' }}>{item.value.suci}</Col>
                                    <Col  style={{ borderRight: '1px solid #ddd' }}>{item.value.guti}</Col>
                                    <Col  style={{ borderRight: '1px solid #ddd' }}>{item.value.timestamp}</Col>
                                </Row>
                            </div>
                        ):(
                            <div className="capture_item" key={item.value.id}>
                            <Row>
                            <Col xs={1} md={1} xl={1}><Spinner animation="border"/></Col>
                            <Col>{item.value.suci}</Col>
                            <Col>{item.value.guti}</Col>
                            <Col>{item.value.timestamp}</Col>
                        </Row>
                </div>
                )
            ))}
            </div>
        </Container>
    );
}