import * as ASN1 from './asn1/asn1';
import * as pkcs11js from 'pkcs11js';
import { Der } from './der';

export default class X509PublicKeyCert {
    public CKA_SUBJECT: number | boolean | string | Buffer;
    public CKA_ID: number | boolean | string | Buffer;
    public CKA_ISSUER: number | boolean | string | Buffer;
    public CKA_SERIAL_NUMBER: number | boolean | string | Buffer;
    public CKA_VALUE: number | boolean | string | Buffer;
    public CKA_URL: number | boolean | string | Buffer;
    public CKA_HASH_OF_SUBJECT_PUBLIC_KEY: number | boolean | string | Buffer;
    public CKA_HASH_OF_ISSUER_PUBLIC_KEY: number | boolean | string | Buffer;
    public CKA_JAVA_MIDP_SECURITY_DOMAIN: number | boolean | string | Buffer;
    public CKA_NAME_HASH_ALGORITHM: number | boolean | string | Buffer;
    public CKA_CERTIFICATE_TYPE: number | boolean | string | Buffer;
    public CKA_START_DATE: number | boolean | string | Buffer;
    public CKA_END_DATE: number | boolean | string | Buffer;

    public PKCS11: pkcs11js.PKCS11;

    constructor(pkcs11: pkcs11js.PKCS11) {
        this.PKCS11 = pkcs11;
    }

    public getCertificate(session: Buffer) {
        // Obtain the certificate object from the eToken
        this.PKCS11.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_CERTIFICATE }
        ]);

        var hObject: Buffer = this.PKCS11.C_FindObjects(session);
        
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
                { type: pkcs11js.CKA_START_DATE },
                { type: pkcs11js.CKA_END_DATE }
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
            this.CKA_START_DATE = attrs[10].value;
            this.CKA_END_DATE = attrs[11].value;
            // this.CKA_NAME_HASH_ALGORITHM = attrs[].value;  // Not suported

            // Iterate the next object found if exists
            hObject = this.PKCS11.C_FindObjects(session);
        }
        // Close the obtain process of info
        this.PKCS11.C_FindObjectsFinal(session);
    }

    public getBase64Certificate() {
        return (this.CKA_VALUE as Buffer).toString('base64');
    }

    public getSubject() {
        return (this.CKA_SUBJECT as Buffer).toString('base64');
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