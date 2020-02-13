package lu.pata.cert.crt.certificate.tbscertificate;

import lu.pata.cert.CertException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Enumeration;

public class EccPublicKeyParams {
    private BigInteger EC_P;
    private BigInteger EC_A;
    private BigInteger EC_B;
    private BigInteger EC_X;
    private BigInteger EC_Y;
    private BigInteger EC_N;
    private BigInteger EC_H;

    private ECCurve curve;
    private ECPoint EC_G;

    public EccPublicKeyParams(ASN1Sequence eccPkSeq) throws CertException {
        Enumeration eccPkEnum=eccPkSeq.getObjects();
        ASN1ObjectIdentifier oid=(ASN1ObjectIdentifier)eccPkEnum.nextElement();
        if(!oid.getId().equals("1.2.840.10045.2.1")) throw new CertException("PublicKey should be ECC OID 1.2.840.10045.2.1. Actual: "+oid.getId());

        parseEccParams((ASN1Sequence)eccPkEnum.nextElement());
    }

    private void parseEccParams(ASN1Sequence eccParamsSeq) throws CertException {
        Enumeration eccParamsEnum=eccParamsSeq.getObjects();

        ASN1Integer version=(ASN1Integer)eccParamsEnum.nextElement();

        ASN1Sequence primeFieldSeq=(ASN1Sequence)eccParamsEnum.nextElement();
        Enumeration primeFieldEnum=primeFieldSeq.getObjects();
        if(!((ASN1ObjectIdentifier)primeFieldEnum.nextElement()).getId().equals("1.2.840.10045.1.1")) throw new CertException("Expected ECC Prime Field OID 1.2.840.10045.1.1.");
        ASN1Integer primeField=(ASN1Integer)primeFieldEnum.nextElement();
        EC_P=primeField.getValue();

        ASN1Sequence curveSeq=(ASN1Sequence)eccParamsEnum.nextElement();
        Enumeration curveEnum=curveSeq.getObjects();
        ASN1OctetString a=(ASN1OctetString)curveEnum.nextElement();
        EC_A=new BigInteger(1,a.getOctets());
        ASN1OctetString b=(ASN1OctetString)curveEnum.nextElement();
        EC_B=new BigInteger(1,b.getOctets());

        ASN1OctetString base=(ASN1OctetString)eccParamsEnum.nextElement();
        int bl=(base.getOctets().length-1)/2; //The byte array contains values of X and Y stick together and preceded by 0x04.
        byte[] bx=new byte[bl];
        System.arraycopy(base.getOctets(),1,bx,0,bl);
        byte[] by=new byte[bl];
        System.arraycopy(base.getOctets(),bl+1,by,0,bl);
        EC_X=new BigInteger(1,bx);
        EC_Y=new BigInteger(1,by);

        ASN1Integer order=(ASN1Integer)eccParamsEnum.nextElement();
        EC_N=order.getValue();

        ASN1Integer cofactor=(ASN1Integer)eccParamsEnum.nextElement();
        EC_H=cofactor.getValue();

        curve=new ECCurve.Fp(EC_P, EC_A, EC_B,EC_N,EC_H);
        EC_G=curve.createPoint(EC_X, EC_Y);
    }

    public ECCurve getCurve(){
        return curve;
    }

    public ECPoint getGenerator(){
        return EC_G;
    }

    public BigInteger getEC_N() {
        return EC_N;
    }
}
