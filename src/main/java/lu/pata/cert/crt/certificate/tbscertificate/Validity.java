package lu.pata.cert.crt.certificate.tbscertificate;

import lu.pata.cert.CertException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;

import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;

public class Validity {
    private Date creationDate;
    private Date expirationDate;

    public Validity(ASN1Primitive data) throws CertException {
        if(!(data instanceof ASN1Sequence)) throw new CertException("ASN1Sequence expected as input data Validity.");
        ASN1Sequence dataSeq=(ASN1Sequence)data;
        Enumeration dataEnum=dataSeq.getObjects();
        ASN1UTCTime creation=(ASN1UTCTime)dataEnum.nextElement();
        ASN1UTCTime expiration=(ASN1UTCTime)dataEnum.nextElement();

        try {
            creationDate=creation.getDate();
            expirationDate=expiration.getDate();
        } catch (ParseException e) {
            throw new CertException("Cannot parse validity date: "+e.getMessage());
        }
    }

    public boolean verify(){
        Date current=new Date();
        if(creationDate.getTime()<current.getTime() && current.getTime()<expirationDate.getTime()){
            return true;
        } else {
            return false;
        }
    }
}
