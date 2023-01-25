import base64
from dataclasses import dataclass

from pyasn1 import debug, codec, error


@dataclass
class iefAssociationRecord():
    supi: str
    fivegguti: str
    timestmp: str  # utc
    tai: str
    ncgi: {}  # nCI -> v, pLMNID -> v
    ncgi_time: str  # last ueLocationTimestmp or nCGIs available
    suci: str
    pei: str
    list_of_tai: [str]


@dataclass
class iefDeassociationRecord():
    supi: str
    suci: str
    fivegguti: str
    timestmp: str
    ncgi: {}  # nCI -> v, pLMNID ->
    ncgi_time: str


@dataclass
class iefRecord():
    isAssoc: int = 1
    error: bytes = "None".encode()
    assoc: iefAssociationRecord = None
    deassoc: iefDeassociationRecord = None


# Auto-generated by asn1ate v.0.6.1.dev0 from TS33128IdentityAssociation.asn
# (last modified on 2023-01-03 15:52:59.340291)

# TS33128IdentityAssociation
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful
from pyasn1.codec.ber import  decoder

from datetime import datetime

def get_time_utc() -> str:
    return datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
class EUI64(univ.OctetString):
    pass


EUI64.subtypeSpec = constraint.ValueSizeConstraint(8, 8)


class FiveGGUTI(univ.OctetString):
    pass


FiveGGUTI.subtypeSpec = constraint.ValueSizeConstraint(10, 10)


class TAI(univ.OctetString):
    pass


TAI.subtypeSpec = constraint.ValueSizeConstraint(6, 6)


class FiveGSTAIList(univ.SequenceOf):
    pass


FiveGSTAIList.componentType = TAI()


class NCI(univ.BitString):
    pass




class PLMNID(univ.OctetString):
    pass


PLMNID.subtypeSpec = constraint.ValueSizeConstraint(3, 3)


class NCGI(univ.Sequence):
    pass


NCGI.componentType = namedtype.NamedTypes(
    namedtype.NamedType('pLMNID', PLMNID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('nCI', NCI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
)


class IMEI(char.NumericString):
    pass


IMEI.subtypeSpec = constraint.ValueSizeConstraint(14, 14)


class IMEISV(char.NumericString):
    pass


IMEISV.subtypeSpec = constraint.ValueSizeConstraint(16, 16)


class MACAddress(univ.OctetString):
    pass


MACAddress.subtypeSpec = constraint.ValueSizeConstraint(6, 6)


class PEI(univ.Choice):
    pass


PEI.componentType = namedtype.NamedTypes(
    namedtype.NamedType('iMEI', IMEI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('iMEISV', IMEISV().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('mACAddress', MACAddress().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('eUI64', EUI64().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)))
)


class SUCI(univ.OctetString):
    pass


SUCI.subtypeSpec = constraint.ValueSizeConstraint(8, 3008)


class IMSI(char.NumericString):
    pass


IMSI.subtypeSpec = constraint.ValueSizeConstraint(6, 15)


class NAI(char.UTF8String):
    pass


class SUPI(univ.Choice):
    pass


SUPI.componentType = namedtype.NamedTypes(
    namedtype.NamedType('iMSI', IMSI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('nAI', NAI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
)


class IEFAssociationRecord(univ.Sequence):
    pass


IEFAssociationRecord.componentType = namedtype.NamedTypes(
    namedtype.NamedType('sUPI', SUPI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
    namedtype.NamedType('fiveGGUTI', FiveGGUTI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('timestamp', useful.GeneralizedTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('tAI', TAI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('nCGI', NCGI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
    namedtype.NamedType('nCGITime', useful.GeneralizedTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.OptionalNamedType('sUCI', SUCI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.OptionalNamedType('pEI', PEI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
    namedtype.OptionalNamedType('fiveGSTAIList', FiveGSTAIList().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)))
)


class IEFDeassociationRecord(univ.Sequence):
    pass


IEFDeassociationRecord.componentType = namedtype.NamedTypes(
    namedtype.NamedType('sUPI', SUPI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
    namedtype.NamedType('fiveGGUTI', FiveGGUTI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('timestamp', useful.GeneralizedTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('nCGI', NCGI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
    namedtype.NamedType('nCGITime', useful.GeneralizedTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.OptionalNamedType('sUCI', SUCI().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)))
)


class IEFKeepaliveMessage(univ.Sequence):
    pass


IEFKeepaliveMessage.componentType = namedtype.NamedTypes(
    namedtype.NamedType('sequenceNumber', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
)


class IEFRecord(univ.Choice):
    pass


IEFRecord.componentType = namedtype.NamedTypes(
    namedtype.NamedType('associationRecord', IEFAssociationRecord().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
    namedtype.NamedType('deassociationRecord', IEFDeassociationRecord().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
    namedtype.NamedType('keepalive', IEFKeepaliveMessage().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
    namedtype.NamedType('keepaliveResponse', IEFKeepaliveMessage().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)))
)


class RELATIVE_OID(univ.ObjectIdentifier):
    pass

oid = RELATIVE_OID((0,4,1,20,2,16,3,2,4,1))


class IEFMessage(univ.Sequence):
    pass


IEFMessage.componentType = namedtype.NamedTypes(
    namedtype.NamedType('iEFRecordOID', oid),
    namedtype.NamedType('record', IEFRecord().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
)

def decode(msg: bytes)->iefRecord:
    decoded_record = iefRecord()

    try:
        msg = base64.b64decode(msg)

        message = decoder.decode(msg, asn1Spec=IEFMessage())[0]

        record = message.getComponentByName("record")

        if record is None:
            raise Exception("ASN1 Decoding Error for IEFRecord")

        if record['deassociationRecord'].isValue:
            decoded_record.deassoc = iefDeassociationRecord(
                supi=record['deassociationRecord']['sUPI']['iMSI']._value.encode(),
                fivegguti=record['deassociationRecord']['fiveGGUTI']._value,
                ncgi={
                    'pLMNID':record['deassociationRecord']['nCGI']['pLMNID']._value,
                    'nCI':str(int(record['deassociationRecord']['nCGI']['nCI']._value)).encode(),
                },
                ncgi_time=record['deassociationRecord']['nCGITime']._value[:-8].encode(),
                timestmp=record['deassociationRecord']['timestamp']._value[:-8].encode(),
                suci=record['deassociationRecord']['sUCI']._value,
            )
            decoded_record.isAssoc = 0
            return decoded_record

        # needed for God knows whatever reason, we need to reinstantiate record

        message = decoder.decode(msg, asn1Spec=IEFMessage())[0]
        record = message.getComponentByName("record")
        if record is None:
            raise Exception("ASN1 Decoding Error for IEFRecord")

        if record['associationRecord'].isValue:
            decoded_record.assoc = iefAssociationRecord(
                supi=record['associationRecord']['sUPI']['iMSI']._value.encode(),
                suci=record['associationRecord']['sUCI']._value,
                fivegguti=record['associationRecord']['fiveGGUTI']._value,
                ncgi={
                    'pLMNID':record['associationRecord']['nCGI']['pLMNID']._value,
                      'nCI':str(int(record['associationRecord']['nCGI']['nCI']._value)).encode()
                },
                ncgi_time=record['associationRecord']['nCGITime']._value[:-8].encode(),
                tai=record['associationRecord']['tAI']._value,
                timestmp=record['associationRecord']['timestamp']._value[:-8].encode(),
                list_of_tai=[str(tai).encode() for tai in record['associationRecord']['fiveGSTAIList']._componentValues.values()],
                pei=record['associationRecord']['pEI']['iMEISV']._value.encode(),
            )
            decoded_record.isAssoc = 1
            return decoded_record
    except Exception as ex:
        decoded_record.error = str(ex).encode()
        return decoded_record


if __name__ == "__main__":
    print(decode(b'MIGvBgkEARQCEAMCBAGigaGhgZ6hC4EJMTIzNDU2Nzg5ggowMTAyMDMwNDA1gxsyMDIzLTAxLTI1VDEwOjQyOjM2LjUwOTM3M1qEBjAxMDEwMaUNgQM5OTmCBgQAAAABAIYbMjAyMy0wMS0yNVQxMDo0MjozNi41MDkzOTJahwxBQUFBQUFBQUFBQUGoEoIQNDM3MDgxNjEyNTgxNjE1MakQBAYwMTAxMDEEBjEwMTAxMA==='))
    print(decode(b'MH8GCQQBFAIQAwIEAaJyonChC4EJMTIzNDU2Nzg5ggowMTAyMDMwNDA1gxsyMDIzLTAxLTI1VDEwOjI1OjMwLjA2MzkwNVqkDYEDOTk5ggYEAAAAAQCFGzIwMjMtMDEtMjVUMTA6MjU6MzAuMDYzOTMxWoYMQUFBQUFBQUFBQUFB='
                 ))