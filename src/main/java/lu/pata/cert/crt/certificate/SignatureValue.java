package lu.pata.cert.crt.certificate;

import lu.pata.cert.CertException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

public class SignatureValue {
    private BigInteger r;
    private BigInteger s;

    public SignatureValue(ASN1Primitive data) throws CertException {
        if(!(data instanceof ASN1BitString)) throw new CertException("ASN1BitString expected as input data SignatureValue.");
        ASN1BitString bsAsn=(ASN1BitString)data;

        /*
        We are considering only EC signatures.
        EC signature should contain two numbers called r and s. In ASN those are encoded in a sequence.
        */
        ASN1Sequence sigSeq;
        try {
            sigSeq = (ASN1Sequence)ASN1Primitive.fromByteArray(bsAsn.getBytes());
        } catch (IOException e) {
            throw new CertException("Signature should be stored in ASN1Sequence.");
        }
        Enumeration sigEnum=sigSeq.getObjects();
        r=((ASN1Integer)sigEnum.nextElement()).getValue();
        s=((ASN1Integer)sigEnum.nextElement()).getValue();
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }
}
