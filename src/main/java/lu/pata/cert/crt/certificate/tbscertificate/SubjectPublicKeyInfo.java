package lu.pata.cert.crt.certificate.tbscertificate;

import lu.pata.cert.CertException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Enumeration;

public class SubjectPublicKeyInfo {
    private EccPublicKeyParams ecc;
    private ECPoint publicKey;

    public SubjectPublicKeyInfo(ASN1Primitive data) throws CertException {
        if(!(data instanceof ASN1Sequence)) throw new CertException("ASN1Sequence expected as input data SubjectPublicKeyInfo.");
        ASN1Sequence pkSeq=(ASN1Sequence)data;
        Enumeration pkEnum=pkSeq.getObjects();

        ASN1Sequence publicKeyParams=(ASN1Sequence)pkEnum.nextElement();
        ASN1BitString publicKeyValue=(ASN1BitString)pkEnum.nextElement();

        int bl=(publicKeyValue.getOctets().length-1)/2; //The byte array contains values of X and Y stick together and preceded by 0x04.
        byte[] bx=new byte[bl];
        System.arraycopy(publicKeyValue.getOctets(),1,bx,0,bl);
        byte[] by=new byte[bl];
        System.arraycopy(publicKeyValue.getOctets(),bl+1,by,0,bl);
        BigInteger px=new BigInteger(1,bx);
        BigInteger py=new BigInteger(1,by);

        ecc=new EccPublicKeyParams(publicKeyParams);
        publicKey=ecc.getCurve().createPoint(px, py);
    }

    public EccPublicKeyParams getEccParams() {
        return ecc;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }
}
