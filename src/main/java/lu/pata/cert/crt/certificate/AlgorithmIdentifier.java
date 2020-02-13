package lu.pata.cert.crt.certificate;

import lu.pata.cert.CertException;
import lu.pata.cert.crt.certificate.algorithmidentifier.SignatureAlgorithms;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.util.Enumeration;

public class AlgorithmIdentifier {
    private String oid;

    public AlgorithmIdentifier(ASN1Primitive data) throws CertException {
        if(!(data instanceof ASN1Sequence)) throw new CertException("ASN1Sequence expected as input data AlgorithmIdentifier.");
        ASN1Sequence algAsn=(ASN1Sequence)data;

        Enumeration algEnum=algAsn.getObjects();
        ASN1Primitive oIdAsn=(ASN1Primitive) algEnum.nextElement();

        if(!(oIdAsn instanceof ASN1ObjectIdentifier)) throw new CertException("AlgorithmIdentifier must contain ASN1ObjectIdentifier.");
        ASN1ObjectIdentifier oId=(ASN1ObjectIdentifier)oIdAsn;
        if(!SignatureAlgorithms.supportOID(oId.getId())) throw new CertException("Signature OID not supported: "+oId.getId());
        this.oid=oId.getId();
    }

    public String getOid() {
        return oid;
    }
}
