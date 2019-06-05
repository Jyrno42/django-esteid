from oscrypto.asymmetric import load_certificate

from esteid import certs
from .ocsp import OCSP
from .tsa import TSA


def make_lt_ts(xml_signature, is_demo=False):
    """

    :param XmlSignature xml_signature:
    """
    subject_cert = xml_signature.get_certificate()
    issuer_cn = subject_cert.asn1.issuer.native['common_name']
    issuer_cert = load_certificate(certs.get_certificate_file_name(issuer_cn))

    # Get an OCSP status confirmation
    ocsp = OCSP(url=OCSP.DEMO_URL if is_demo else None)
    ocsp.validate(subject_cert, issuer_cert, xml_signature.get_signature_value())

    # Embed the OCSP response
    xml_signature.add_ocsp_response(ocsp)

    # Get a signature TimeStamp
    tsa = TSA(url=TSA.DEMO_URL if is_demo else None)
    tsr = tsa.get_timestamp(xml_signature.get_timestamp_response())
    xml_signature.add_timestamp_response(tsr)
