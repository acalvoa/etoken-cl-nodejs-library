import * as pkcs11js from 'pkcs11js';

export class PrivateKey {
    private CKA_CLASS;
    private CKA_TOKEN;
    private CKA_PRIVATE;
    private CKA_EXTRACTABLE;
    private CKA_SENSITIVE;
    private CKA_DECRYPT;
    private CKA_UNWRAP;
    private CKA_SIGN_RECOVER;
    private CKA_SIGN;
    private CKA_ID;
    private CKA_LABEL;

    private PKCS11;
    private privateKey;

    constructor(pkcs11: pkcs11js.PKCS11, signOnly: boolean = true) {
        this.CKA_CLASS = pkcs11js.CKO_PRIVATE_KEY;
        this.CKA_TOKEN = false;
        this.CKA_PRIVATE = true;
        this.CKA_EXTRACTABLE = false;
        this.CKA_SENSITIVE = true;
        this.CKA_DECRYPT = !signOnly;
        this.CKA_UNWRAP = !signOnly;
        this.CKA_SIGN_RECOVER = true;
        this.CKA_SIGN = true;
        // Not suported for token private key values in memory
        //this.CKA_ID = "PRIV"+Math.floor(Math.random()*200) + new Date().getTime().toString();
        //this.CKA_LABEL = "CGR-Signer Private Key";
        this.PKCS11 = pkcs11;
    }

    public getTemplate() {
        return [
            { type: pkcs11js.CKA_CLASS, value: this.CKA_CLASS },
            { type: pkcs11js.CKA_TOKEN, value: this.CKA_TOKEN },
            { type: pkcs11js.CKA_PRIVATE, value: this.CKA_PRIVATE },
            { type: pkcs11js.CKA_EXTRACTABLE, value: this.CKA_EXTRACTABLE },
            { type: pkcs11js.CKA_SENSITIVE, value: this.CKA_SENSITIVE },
            { type: pkcs11js.CKA_DECRYPT, value: this.CKA_DECRYPT },
            { type: pkcs11js.CKA_UNWRAP, value: this.CKA_UNWRAP },
            { type: pkcs11js.CKA_SIGN_RECOVER, value: this.CKA_SIGN_RECOVER },
            { type: pkcs11js.CKA_SIGN, value: this.CKA_SIGN }
        ];
    }

    public getTokenPrivateKey(session: any) {
        // Obtain the certificate object from the eToken
        this.PKCS11.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY }
        ]);
        var hObject = this.PKCS11.C_FindObjects(session);

        while (hObject) {
            // Define the attrs to obtain from the eToken
            var attrs = this.PKCS11.C_GetAttributeValue(session, hObject, [
                { type: pkcs11js.CKA_CLASS },
                { type: pkcs11js.CKA_TOKEN },
                { type: pkcs11js.CKA_PRIVATE },
                { type: pkcs11js.CKA_EXTRACTABLE },
                { type: pkcs11js.CKA_SENSITIVE },
                { type: pkcs11js.CKA_DECRYPT },
                { type: pkcs11js.CKA_UNWRAP },
                { type: pkcs11js.CKA_SIGN_RECOVER },
                { type: pkcs11js.CKA_SIGN },
                { type: pkcs11js.CKA_ID },
                { type: pkcs11js.CKA_LABEL },
                { type: pkcs11js.CKA_MODULUS },
                { type: pkcs11js.CKA_PUBLIC_EXPONENT },
                // Not suported in this mode
                //{ type: pkcs11js.CKA_PRIVATE_EXPONENT },
                //{ type: pkcs11js.CKA_PRIME_1 },
                //{ type: pkcs11js.CKA_PRIME_2 },
                //{ type: pkcs11js.CKA_EXPONENT_1 },
                //{ type: pkcs11js.CKA_EXPONENT_2 },
                //{ type: pkcs11js.CKA_COEFFICIENT }
            ]);

            // Asign the properties into the Object attributes
            this.privateKey = {
                CKA_CLASS: attrs[0].value,
                CKA_TOKEN: attrs[1].value,
                CKA_PRIVATE: attrs[2].value,
                CKA_EXTRACTABLE: attrs[3].value,
                CKA_SENSITIVE: attrs[4].value,
                CKA_DECRYPT: attrs[5].value,
                CKA_UNWRAP: attrs[6].value,
                CKA_SIGN_RECOVER: attrs[7].value,
                CKA_SIGN: attrs[8].value,
                CKA_ID: attrs[9].value,
                CKA_LABEL: attrs[10].value,
                CKA_MODULUS: attrs[11].value,
                CKA_PUBLIC_EXPONENT: attrs[12].value,
                // Not suported in this mode
                //CKA_PRIVATE_EXPONENT: attrs[13].value,
                //CKA_PRIME_1: attrs[14].value,
                //CKA_PRIME_2: attrs[15].value,
                //CKA_EXPONENT_1: attrs[16].value,
                //CKA_EXPONENT_2: attrs[17].value,
                //CKA_COEFFICIENT: attrs[18].value
            };

            // Iterate the next object found if exists
            hObject = this.PKCS11.C_FindObjects(session);
        }
        // Close the obtain process of info
        this.PKCS11.C_FindObjectsFinal(session);
    }

    public getPrivateKey(session: any) {
        if (!this.privateKey) this.getTokenPrivateKey(session);
        return this.privateKey;
    }

    public getPrivateKeyBase64(session: any) {
        if (!this.privateKey) this.getTokenPrivateKey(session);
        return {
            CKA_CLASS: this.privateKey.CKA_CLASS.toString('base64'),
            CKA_TOKEN: !!this.privateKey.CKA_TOKEN[0],
            CKA_PRIVATE: !!this.privateKey.CKA_PRIVATE[0],
            CKA_EXTRACTABLE: !!this.privateKey.CKA_EXTRACTABLE[0],
            CKA_SENSITIVE: !!this.privateKey.CKA_SENSITIVE[0],
            CKA_DECRYPT: !!this.privateKey.CKA_DECRYPT[0],
            CKA_UNWRAP: !!this.privateKey.CKA_UNWRAP[0],
            CKA_SIGN_RECOVER: !!this.privateKey.CKA_SIGN_RECOVER[0],
            CKA_SIGN: !!this.privateKey.CKA_SIGN[0],
            CKA_ID: this.privateKey.CKA_ID.toString(),
            CKA_LABEL: this.privateKey.CKA_LABEL.toString(),
            CKA_MODULUS: this.privateKey.CKA_MODULUS.toString('base64'),
            CKA_PUBLIC_EXPONENT: this.privateKey.CKA_PUBLIC_EXPONENT.toString('base64'),
            // Not suported in this mode
            //CKA_PRIVATE_EXPONENT: this.privateKey.CKA_PRIVATE_EXPONENT.toString('base64'),
            //CKA_PRIME_1: this.privateKey.CKA_PRIME_1.toString('base64'),
            //CKA_PRIME_2: this.privateKey.CKA_PRIME_2.toString('base64'),
            //CKA_EXPONENT_1: this.privateKey.CKA_EXPONENT_1.toString('base64'),
            //CKA_EXPONENT_2: this.privateKey.CKA_EXPONENT_2.toString('base64'),
            //CKA_COEFFICIENT: this.privateKey.CKA_COEFFICIENT.toString('base64')
        };
    }
}