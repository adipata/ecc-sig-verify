package lu.pata.cert.crt.certificate;

import lu.pata.cert.CertException;
import lu.pata.cert.crt.certificate.tbscertificate.CertificateSubject;
import lu.pata.cert.crt.certificate.tbscertificate.EccPublicKeyParams;
import lu.pata.cert.crt.certificate.tbscertificate.SubjectPublicKeyInfo;
import lu.pata.cert.crt.certificate.tbscertificate.Validity;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;

public class TBSCertificate {
    private byte[] binaryData;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    public TBSCertificate (ASN1Primitive data) throws CertException, IOException {
        if(!(data instanceof ASN1Sequence)) throw new CertException("ASN1Sequence expected as input data TBSCertificate.");
        binaryData=data.getEncoded();

        ASN1Sequence certSeq=(ASN1Sequence)data;
        Enumeration certEnum=certSeq.getObjects();

        ASN1Primitive version=(ASN1Primitive) certEnum.nextElement();
        ASN1Primitive serialNumber=(ASN1Primitive) certEnum.nextElement();
        ASN1Primitive signature=(ASN1Primitive) certEnum.nextElement();
        CertificateSubject issuer=new CertificateSubject((ASN1Primitive) certEnum.nextElement());
        Validity validity=new Validity((ASN1Primitive) certEnum.nextElement());
        CertificateSubject subject=new CertificateSubject((ASN1Primitive) certEnum.nextElement());
        subjectPublicKeyInfo=new SubjectPublicKeyInfo((ASN1Primitive) certEnum.nextElement());
    }

    public byte[] getHash(AlgorithmIdentifier alg) throws NoSuchAlgorithmException, CertException {
        MessageDigest md;
        switch (alg.getOid()) {
            case "1.2.840.10045.4.1":
                md = MessageDigest.getInstance("SHA-1");
                return md.digest(binaryData);
            case "1.2.840.10045.4.3.2":
                md = MessageDigest.getInstance("SHA-256");
                return md.digest(binaryData);
        }

        throw new CertException("Hashing algorithm is not recognized.");
    }

    public EccPublicKeyParams getEccParams() {
        return subjectPublicKeyInfo.getEccParams();
    }

    public ECPoint getPublicKey() {
        return subjectPublicKeyInfo.getPublicKey();
    }
}
