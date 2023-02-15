export class Event{
    constructor(type){
        this.type = type;
    }

    getType():string{
        return this.type
    }

    static fromJSON(Obj):Event {
        return new Event(Obj.type)
    }

}
export class Capture extends Event{
    constructor(id, suci, guti, timestamp) {
        super("capture")
        this.id = id;
        this.suci = suci;
        this.guti = guti;
        this.timestamp = timestamp;
    }
    static fromJSON(Obj):Capture{
        return new Capture(Obj.id, Obj.suci, Obj.guti, Obj.timestamp)
    }
}

export class Association extends Event{
    constructor(id, supi, suci, guti, startTimestamp, endTimestamp, leakage, latency, error) {
        super("association")
        this.id = id;
        this.supi = supi
        this.suci = suci;
        this.guti = guti;
        this.startTimestamp = startTimestamp;
        this.endTimestamp = endTimestamp;
        this.leakage = leakage;
        this.latency = latency;
        this.error = error;
    }
    static fromJSON(Obj):Association{
        return new Association(Obj.id, Obj.supi, Obj.suci, Obj.guti, Obj.startTimestamp, Obj.endTimestamp, Obj.leakage, Obj.latency, Obj.error)
    }
}
