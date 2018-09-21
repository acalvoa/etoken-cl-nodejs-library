import * as pkcs11js from 'pkcs11js';
import * as os from 'os';
import { Token } from './token';
import { Signer } from './signer';
import { SignAlgorithm } from '../interfaces/signalgorithm';

export class Etoken {
    private PKCS11: pkcs11js.PKCS11;
    private tokenReady: boolean;
    private tokensConnected: number[];
    private tokenInUse: any;
    private session: any;

    private LIB_WIN32_PATH: string = '';
    private LIB_WIN64_PATH: string = '';
    private LIB_LINUX_PATH: string = '/usr/lib/libeToken.so';
    //private LIB_LINUX_PATH: string = '/usr/lib/libsoftokn3.so';
    private LIB_IOS_PATH: string = '';

    constructor() {
        this.PKCS11 = new pkcs11js.PKCS11();
        this.tokenReady = false;
        this.initializeOS();
        this.searchTokensConnected();
    }

    private initializeOS() {
        let path;
        switch(os.platform()) {
            case 'darwin':
                path = this.LIB_IOS_PATH;
                break;
            case 'win32':
                if(os.arch() === 'x64') {
                    path = this.LIB_WIN64_PATH;
                } else {
                    path = this.LIB_WIN32_PATH;
                }
                break;
            case 'linux':
                path = this.LIB_LINUX_PATH;
                break;
            default:
                console.error('This SO is not supported');
        }
        if(path) this.initialize(path);
    }

    private initialize(path: string) {
        try {
            this.PKCS11.load(path);
            this.PKCS11.C_Initialize();
        } catch(e) {
            console.error('The loadf of shared library has an error');
            console.error(e.message);
        }
    }

    public getInfo(): any {
        try {
            return this.PKCS11.C_GetInfo();
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public getSlots(): any[] {
        try {
            return this.PKCS11.C_GetSlotList();
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public getSlotInfo(slot: number): any {
        try {
            const slots = this.getSlots();
            return this.PKCS11.C_GetSlotInfo(slots[slot]);
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public getSlotsInfo(): any {
        try {
            const slots = this.getSlots();
            let slotsInfo = [];
            for (let i=0; i < slots.length; i++) {
                slotsInfo.push(this.PKCS11.C_GetSlotInfo(slots[i]));
            }
            return slotsInfo;
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public searchTokensConnected() {
        try {
            const slots = this.getSlots();
            let tokens = [];

            for (let i=0; i < slots.length; i++) {
                let slot = this.PKCS11.C_GetSlotInfo(slots[i]);
                if (slot['flags'] === 7 && slot['slotDescription'].trim() !== '') {
                    tokens.push(i);
                }
            }

            this.tokenReady = (tokens.length > 0);
            this.tokensConnected = tokens;
        } catch (e) {
            console.error(e);
            this.finalize();
        }
    }

    public getTokensConnected() {
        return this.tokensConnected;
    }

    public getTokenConnectedInfo(token: number) {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            if (typeof this.tokensConnected[token] === 'undefined') throw new Error('Token index not exists');
            return new Token(this.tokensConnected[token], this.PKCS11.C_GetTokenInfo(this.getSlotbyToken(token)), this.getSlotbyToken(token));
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    public getTokensConnectedInfo(): Token[] {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            let tokens: Token[] = [];

            for (let i=0; i < this.tokensConnected.length; i++) {
                tokens.push(this.getTokenConnectedInfo(i));
            }
            return tokens;
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    private getSlotbyToken(token: number) {
        const slots = this.getSlots();
        return slots[this.tokensConnected[token]];
    }

    public getSignMechanisms(token: number) {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            let mechsInfo = [];
            var mechs = this.PKCS11.C_GetMechanismList(this.getSlotbyToken(token));

            for (let i=0; i < mechs.length; i++) {
                mechsInfo.push({
                    id: mechs[i],
                    properties: this.PKCS11.C_GetMechanismInfo(this.getSlotbyToken(token), mechs[i])
                });
            }
            return mechsInfo;
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    private initSession(token: number) {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            this.session = this.PKCS11.C_OpenSession(this.getSlotbyToken(token), pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);
            return this.PKCS11.C_GetSessionInfo(this.session);
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    public login(token: number, password: string) {
        try {
            this.initSession(token);
            if (!this.session) throw new Error('The token session is not already yet');
            this.PKCS11.C_Login(this.session, 1, password);
            this.tokenInUse = this.getTokenConnectedInfo(token);
            return true;
        } catch(e) {
            this.finalize();
            return false;
        }
    }

    public verifyTokenInUse() {
        try {
            if (!this.tokenInUse) throw new Error('No are a token in use');
            return this.tokenInUse.verifytoken(this);
        } catch(e) {
            this.finalize();
            return false;
        }
    }

    public sign(algorithm: SignAlgorithm, data: Buffer): Signer {
        if(this.verifyTokenInUse()) {
            let signer = new Signer(algorithm, this.PKCS11, this.session);
            signer.sign(data);
            return signer;
        }
        return null;
    }

    public signBase64(algorithm: SignAlgorithm, data: string): Signer {
        if(this.verifyTokenInUse()) {
            let signer = new Signer(algorithm, this.PKCS11, this.session);
            signer.signBase64(data);
            return signer;
        }
        return null;
    }

    public finalize() {
        try {
            this.logout();
            this.closeSession();
            this.PKCS11.C_Finalize();
            return true;
        } catch(e) {
            return false;
        }
    }

    public closeSession() {
        try {
            if (this.session) this.PKCS11.C_CloseSession(this.session);
            return true;
        } catch(e) {
            return false;
        }
    }

    public logout() {
        try {
            if (this.session) this.PKCS11.C_Logout(this.session);
            return true;
        } catch(e) {
            return false;
        }
    }
}

module.exports = Etoken;