import * as pkcs11js from 'pkcs11js';
import * as PrivateKey from './privatekey';
import * as PublicKey  from './publickey';
import * as SignAlgorithm  from '../interfaces/signalgorithm';
import * as X509PublicKeyCert from './x509publickeycet';
import { SignData } from '../interfaces/signdata';

export class Signer {
    private publicKey: PublicKey.PublicKey;
    private privateKey: PrivateKey.PrivateKey;
    private keys: any;
    private algorithm: SignAlgorithm.SignAlgorithm;
    private data: Buffer;
    private pkcs11: pkcs11js.PKCS11;
    private session: any;

    // Signature Objects
    private signature;
    private x509Cert;


    constructor(algorithm: SignAlgorithm.SignAlgorithm , pkcs11: pkcs11js.PKCS11, session: any) {
        this.algorithm = algorithm;
        this.privateKey = new PrivateKey.PrivateKey(pkcs11, true);
        this.publicKey = new PublicKey.PublicKey(pkcs11, true);
        this.pkcs11 = pkcs11;
        this.session = session;
    }

    public generatePairKeys() {
        this.keys = this.pkcs11.C_GenerateKeyPair(
            this.session, 
            { mechanism: pkcs11js.CKM_RSA_PKCS_KEY_PAIR_GEN, parameter: null }, 
            this.publicKey.getTemplate(), 
            this.privateKey.getTemplate()
        );
    }

    public signBase64(data: string): string {
        return this.sign(this.base64_decode(data));
    }

    public sign(data: Buffer): string {
        this.data = data;
        this.generatePairKeys();
        this.pkcs11.C_SignInit(this.session, { mechanism: this.algorithm.id, parameter: null }, this.keys.privateKey);
        this.pkcs11.C_SignUpdate(this.session, data);
        this.signature = this.pkcs11.C_SignFinal(this.session, new Buffer(this.algorithm.outputBits));
        this.generateX509Certificate();
        return this.getSignature();
    }

    private base64_decode(base64str) {
        // create buffer object from base64 encoded string
        var bits = new Buffer(base64str, 'base64');
        // return the buffer
        return bits;
    }

    public getSignature() {
        try {
            if(!this.signature) throw new Error('The signature is not generated previusly.');
            return this.signature.toString('base64');
        } catch (e) {
            console.error(e)
        }
    }

    private generateX509Certificate() {
        const x509Cert = new X509PublicKeyCert.X509PublicKeyCert(this.pkcs11);
        x509Cert.getCertificate(this.session);
        this.x509Cert = x509Cert;
    }

    public getx509Certificate(): X509PublicKeyCert.X509PublicKeyCert {
        try {
            if(!this.x509Cert) throw new Error('First you need sign a data to generate a x509 certificate.');
            return this.x509Cert;
        } catch (e) {
            console.error(e)
        }
    }

    public getPublicKey() {
        try {
            if(!this.publicKey) throw new Error('First you need generate a public key.');
            return this.publicKey.getPublicKey(this.session);
        } catch (e) {
            console.error(e)
        }
    }

    public getPublicKeyBase64() {
        try {
            if(!this.publicKey) throw new Error('First you need generate a public key.');
            return this.publicKey.getPublicKeyBase64(this.session);
        } catch (e) {
            console.error(e)
        }
    }

    public getPrivateKey() {
        try {
            if(!this.privateKey) throw new Error('First you need generate a private key.');
            return this.privateKey.getPrivateKey(this.session);
        } catch (e) {
            console.error(e)
        }
    }

    public getPrivateKeyBase64() {
        try {
            if(!this.privateKey) throw new Error('First you need generate a private key.');
            return this.privateKey.getPrivateKeyBase64(this.session);
        } catch (e) {
            console.error(e)
        }
    }

    public getSignData(): SignData {
        return {
            signature: this.getSignature(),
            x509_cert: {
                certificate: this.getx509Certificate().getBase64Certificate(),
                subject: this.getx509Certificate().getSubject(),
                formated_subject: this.getx509Certificate().getFormatSubject()
            },
            public_key: this.keys.publicKey.toString('base64'),
            private_key: {
                modulus: this.getPrivateKeyBase64().CKA_MODULUS,
                public_exponent: this.getPrivateKeyBase64().CKA_PUBLIC_EXPONENT
            }
        }
    }

    public verify(): boolean {
        this.pkcs11.C_VerifyInit(this.session, { mechanism: this.algorithm.id, parameter: null  }, this.keys.publicKey);
        this.pkcs11.C_VerifyUpdate(this.session, this.data);
        
        return this.pkcs11.C_VerifyFinal(this.session, this.signature);
    }
}