package lu.pata.cert.crt;

import lu.pata.cert.CertException;
import lu.pata.cert.crt.certificate.AlgorithmIdentifier;
import lu.pata.cert.crt.certificate.SignatureValue;
import lu.pata.cert.crt.certificate.TBSCertificate;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Enumeration;

/**
 * Parse according to https://tools.ietf.org/html/rfc5280
 */
public class Certificate {
    private TBSCertificate tbsCertificate;
    private AlgorithmIdentifier algorithmIdentifier;
    private SignatureValue signatureValue;

    public Certificate(byte[] certData) throws IOException, CertException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidParameterSpecException, InvalidKeySpecException, InvalidKeyException {
        ASN1InputStream certIn = new ASN1InputStream(new ByteArrayInputStream(certData));
        ASN1Primitive certAsn = certIn.readObject();
        if(!(certAsn instanceof ASN1Sequence)) throw new CertException("CertData needs to be ASN1Sequence (in root).");

        //Decompose the ASN certificate
        ASN1Sequence seqRoot = (ASN1Sequence) certAsn;
        Enumeration secEnum = seqRoot.getObjects();
        tbsCertificate=new TBSCertificate((ASN1Primitive) secEnum.nextElement());
        algorithmIdentifier=new AlgorithmIdentifier((ASN1Primitive) secEnum.nextElement());
        signatureValue=new SignatureValue((ASN1Primitive) secEnum.nextElement());
    }

    public ECPoint getPublicKey(){
        return tbsCertificate.getPublicKey();
    }

    public boolean verifyWith(Certificate trust) throws CertException, NoSuchAlgorithmException {
        BigInteger hash=new BigInteger(1,tbsCertificate.getHash(algorithmIdentifier));
        BigInteger w = signatureValue.getS().modInverse(tbsCertificate.getEccParams().getEC_N());

        BigInteger u1 = (hash.multiply(w)).mod(tbsCertificate.getEccParams().getEC_N());
        BigInteger u2 = (signatureValue.getR().multiply(w)).mod(tbsCertificate.getEccParams().getEC_N());

        ECPoint G=tbsCertificate.getEccParams().getGenerator();
        ECPoint Q=trust.getPublicKey();

        ECPoint m1=G.multiply(u1);
        ECPoint m2=Q.multiply(u2);

        ECPoint rez=m1.add(m2).normalize();

        BigInteger x2=new BigInteger(rez.getAffineXCoord().getEncoded());

        if(signatureValue.getR().equals(x2))
            return true;
        else
            return false;
    }
}
