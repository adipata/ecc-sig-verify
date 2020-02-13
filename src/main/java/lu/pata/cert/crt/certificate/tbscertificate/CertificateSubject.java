package lu.pata.cert.crt.certificate.tbscertificate;

import lu.pata.cert.CertException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Used for issuer and also for certificate subject.
 */
public class CertificateSubject {
    private Map<String,String> subject=new HashMap<>();

    public CertificateSubject(ASN1Primitive data) throws CertException {
        if(!(data instanceof ASN1Sequence)) throw new CertException("ASN1Sequence expected as input data Issuer.");
        ASN1Sequence issuerSeq=(ASN1Sequence)data;
        Enumeration issuerEnum=issuerSeq.getObjects();
        while (issuerEnum.hasMoreElements()) {
            OidObject o=new OidObject((ASN1Primitive) issuerEnum.nextElement());
            subject.put(o.getName(),o.getValue());
        }
    }
}
