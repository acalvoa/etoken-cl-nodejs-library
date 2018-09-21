import * as pkcs11js from 'pkcs11js';

export class PublicKey {
    private CKA_MODULUS_BITS;
    private CKA_TOKEN;
    private CKA_CLASS;
    private CKA_KEY_TYPE;
    private CKA_PRIVATE;
    private CKA_ENCRYPT;
    private CKA_WRAP;
    private CKA_VERIFY_RECOVER;
    private CKA_VERIFY;
    private CKA_ID;
    private CKA_LABEL;
    private CKA_PUBLIC_EXPONENT;
    // Pkcs11 Library
    private PKCS11;
    private publicKey;

    constructor(pkcs11: pkcs11js.PKCS11, signOnly: boolean = true) {
        // Asign the pkcs11
        this.PKCS11 = pkcs11;
        // initialize the variables
        this.CKA_MODULUS_BITS = 2048;
        this.CKA_TOKEN = false;
        this.CKA_CLASS = pkcs11js.CKO_PUBLIC_KEY; 
        this.CKA_KEY_TYPE = pkcs11js.CKK_RSA; // value CKK_RSA as defined into the PKCKS11 specification
        this.CKA_PRIVATE = false;
        this.CKA_VERIFY = true;
        this.CKA_VERIFY_RECOVER = true;
        this.CKA_ENCRYPT = !signOnly;
        this.CKA_WRAP = !signOnly;
        this.CKA_ID = "PUB"+Math.floor(Math.random()*200) + new Date().getTime().toString(); // Buffer containing the bytes "test01"
        this.CKA_PUBLIC_EXPONENT = new Buffer([1, 0, 1]);
        this.CKA_LABEL = "CGR-Signer Public Key";
    }

    public getTemplate() {
        return [
            { type: pkcs11js.CKA_CLASS, value: this.CKA_CLASS },
            { type: pkcs11js.CKA_TOKEN, value: this.CKA_TOKEN },
            { type: pkcs11js.CKA_MODULUS_BITS, value: this.CKA_MODULUS_BITS },
            { type: pkcs11js.CKA_KEY_TYPE, value: this.CKA_KEY_TYPE },
            { type: pkcs11js.CKA_PRIVATE, value: this.CKA_PRIVATE },
            { type: pkcs11js.CKA_ENCRYPT, value: this.CKA_ENCRYPT },
            { type: pkcs11js.CKA_WRAP, value: this.CKA_WRAP },
            { type: pkcs11js.CKA_VERIFY_RECOVER, value: this.CKA_VERIFY_RECOVER },
            { type: pkcs11js.CKA_VERIFY, value: this.CKA_VERIFY },
            { type: pkcs11js.CKA_ID, value: new Buffer(this.CKA_ID.split('').map( x => x.charCodeAt(0) )) },
            { type: pkcs11js.CKA_LABEL, value: this.CKA_LABEL },
            { type: pkcs11js.CKA_PUBLIC_EXPONENT, value: this.CKA_PUBLIC_EXPONENT },
        ];
    }

    public getTokenPublicKey(session: any) {
        // Obtain the certificate object from the eToken
        this.PKCS11.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY }
        ]);
        var hObject = this.PKCS11.C_FindObjects(session);

        while (hObject) {
            // Define the attrs to obtain from the eToken
            var attrs = this.PKCS11.C_GetAttributeValue(session, hObject, [
                { type: pkcs11js.CKA_CLASS },
                { type: pkcs11js.CKA_TOKEN },
                { type: pkcs11js.CKA_MODULUS_BITS },
                { type: pkcs11js.CKA_KEY_TYPE },
                { type: pkcs11js.CKA_PRIVATE },
                { type: pkcs11js.CKA_ENCRYPT },
                { type: pkcs11js.CKA_WRAP },
                { type: pkcs11js.CKA_VERIFY_RECOVER },
                { type: pkcs11js.CKA_VERIFY },
                { type: pkcs11js.CKA_ID },
                { type: pkcs11js.CKA_LABEL },
                { type: pkcs11js.CKA_PUBLIC_EXPONENT },
            ]);

            // Asign the properties into the Object attributes
            this.publicKey = {
                CKA_MODULUS_BITS: attrs[0].value,
                CKA_TOKEN: attrs[1].value,
                CKA_CLASS: attrs[2].value,
                CKA_KEY_TYPE: attrs[3].value,
                CKA_PRIVATE: attrs[4].value,
                CKA_ENCRYPT: attrs[5].value,
                CKA_WRAP: attrs[6].value,
                CKA_VERIFY_RECOVER: attrs[7].value,
                CKA_VERIFY: attrs[8].value,
                CKA_ID: attrs[9].value,
                CKA_LABEL: attrs[10].value,
                CKA_PUBLIC_EXPONENT: attrs[11].value
            };

            // Iterate the next object found if exists
            hObject = this.PKCS11.C_FindObjects(session);
        }
        // Close the obtain process of info
        this.PKCS11.C_FindObjectsFinal(session);
    }

    public getPublicKey(session: any) {
        if (!this.publicKey) this.getTokenPublicKey(session);
        return this.publicKey;
    }

    public getPublicKeyBase64(session: any) {
        if (!this.publicKey) this.getTokenPublicKey(session);
        return {
            CKA_MODULUS_BITS: this.publicKey.CKA_MODULUS_BITS.toString('base64'),
            CKA_TOKEN: !!this.publicKey.CKA_TOKEN[0],
            CKA_CLASS: this.publicKey.CKA_CLASS.toString('base64'),
            CKA_KEY_TYPE: this.publicKey.CKA_KEY_TYPE.toString('base64'),
            CKA_PRIVATE:!!this.publicKey.CKA_PRIVATE[0],
            CKA_ENCRYPT: !!this.publicKey.CKA_ENCRYPT[0],
            CKA_WRAP: !!this.publicKey.CKA_WRAP[0],
            CKA_VERIFY_RECOVER: !!this.publicKey.CKA_VERIFY_RECOVER[0],
            CKA_VERIFY: !!this.publicKey.CKA_VERIFY[0],
            CKA_ID: this.publicKey.CKA_ID.toString(),
            CKA_LABEL: this.publicKey.CKA_LABEL.toString(),
            CKA_PUBLIC_EXPONENT: this.publicKey.CKA_PUBLIC_EXPONENT.toString('base64'),
        };
    }
}