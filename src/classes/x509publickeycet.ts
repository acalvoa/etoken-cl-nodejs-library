import * as ASN1 from './asn1/asn1';
import * as pkcs11js from 'pkcs11js';
import { Der } from './der';

export class X509PublicKeyCert {
    public CKA_SUBJECT;
    public CKA_ID;
    public CKA_ISSUER;
    public CKA_SERIAL_NUMBER;
    public CKA_VALUE;
    public CKA_URL;
    public CKA_HASH_OF_SUBJECT_PUBLIC_KEY;
    public CKA_HASH_OF_ISSUER_PUBLIC_KEY;
    public CKA_JAVA_MIDP_SECURITY_DOMAIN;
    public CKA_NAME_HASH_ALGORITHM;
    public CKA_CERTIFICATE_TYPE;

    public PKCS11;

    constructor(pkcs11) {
        this.PKCS11 = pkcs11;
    }

    public getCertificate(session) {
        // Obtain the certificate object from the eToken
        this.PKCS11.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_CERTIFICATE }
        ]);
        var hObject = this.PKCS11.C_FindObjects(session);
        
        while (hObject) {
            // Define the attrs to obtain from the eToken
            var attrs = this.PKCS11.C_GetAttributeValue(session, hObject, [
                { type: pkcs11js.CKA_SUBJECT },
                { type: pkcs11js.CKA_ID },
                { type: pkcs11js.CKA_ISSUER },
                { type: pkcs11js.CKA_SERIAL_NUMBER },
                { type: pkcs11js.CKA_VALUE },
                { type: pkcs11js.CKA_URL },
                { type: pkcs11js.CKA_HASH_OF_SUBJECT_PUBLIC_KEY },
                { type: pkcs11js.CKA_HASH_OF_ISSUER_PUBLIC_KEY },
                { type: pkcs11js.CKA_JAVA_MIDP_SECURITY_DOMAIN },
                { type: pkcs11js.CKA_CERTIFICATE_TYPE },
                // { type: pkcs11js.CKA_NAME_HASH_ALGORITHM }  // Not suported
            ]);

            // Asign the properties into the Object attributes
            this.CKA_SUBJECT = attrs[0].value;
            this.CKA_ID = attrs[1].value;
            this.CKA_ISSUER = attrs[2].value;
            this.CKA_SERIAL_NUMBER = attrs[3].value;
            this.CKA_VALUE = attrs[4].value;
            this.CKA_URL = attrs[5].value;
            this.CKA_HASH_OF_SUBJECT_PUBLIC_KEY = attrs[6].value;
            this.CKA_HASH_OF_ISSUER_PUBLIC_KEY = attrs[7].value;
            this.CKA_JAVA_MIDP_SECURITY_DOMAIN = attrs[8].value;
            this.CKA_CERTIFICATE_TYPE = attrs[9].value;
            // this.CKA_NAME_HASH_ALGORITHM = attrs[].value;  // Not suported

            // Iterate the next object found if exists
            hObject = this.PKCS11.C_FindObjects(session);
        }
        // Close the obtain process of info
        this.PKCS11.C_FindObjectsFinal(session);
    }

    public getBase64Certificate() {
        return this.CKA_VALUE.toString('base64');
    }

    public getSubject() {
        const der = ASN1.decode(this.CKA_SUBJECT);
        return this.CKA_SUBJECT.toString('base64');
    }

    public getFormatSubject() {
        const properties = Der.getDerProperties(ASN1.decode(this.CKA_SUBJECT).getAttrObject());
        const formatedProperties = [];
        for (let i=0; i < properties.length; i++) {
            formatedProperties.push(properties[i]['min_attr'] + '=' + properties[i]['value']);
        }
        return formatedProperties.join(", ");
    }

    
}