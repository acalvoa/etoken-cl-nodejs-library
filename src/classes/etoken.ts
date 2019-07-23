import * as pkcs11js from 'pkcs11js';
import * as os from 'os';
import { Token } from './token';
import { Signer } from './signer';
import { SignAlgorithm } from '../interfaces/signalgorithm';
import MechanismInfo from './mechanismInfo';
import X509PublicKeyCert from './x509publickeycet';
import * as moment from 'moment';

export class Etoken {
    private PKCS11: pkcs11js.PKCS11;
    private tokenReady: boolean;
    private tokensConnected: number[];
    private tokenInUse: Token;
    private session: Buffer;
    private loggedIn: boolean;
    private finalized: boolean;

    private LIB_WIN32_PATH: string = '';
    private LIB_WIN64_PATH: string = '';
    private LIB_LINUX_PATH: string = '/usr/lib/libeToken.so';
    //private LIB_LINUX_PATH: string = '/usr/lib/libsoftokn3.so';
    private LIB_IOS_PATH: string = '';

    constructor() {
        this.PKCS11 = new pkcs11js.PKCS11();
        this.tokenReady = false;
        this.loggedIn = false;
        this.finalized = false;
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

    private initialize(path: string): void {
        try {
            this.PKCS11.load(path);
            this.PKCS11.C_Initialize();
        } catch(e) {
            console.error('The loadf of shared library has an error');
            console.error(e.message);
        }
    }

    public getInfo(): pkcs11js.ModuleInfo {
        try {
            return this.PKCS11.C_GetInfo();
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public getSlots(): Buffer[] {
        try {
            return this.PKCS11.C_GetSlotList(true);
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public getSlotInfo(slot: number): pkcs11js.SlotInfo {
        try {
            const slots = this.getSlots();
            return this.PKCS11.C_GetSlotInfo(slots[slot]);
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public getSlotsInfo(): pkcs11js.SlotInfo[] {
        try {
            const slots = this.getSlots();
            let slotsInfo: pkcs11js.SlotInfo[] = [];
            for (let i=0; i < slots.length; i++) {
                slotsInfo.push(this.PKCS11.C_GetSlotInfo(slots[i]));
            }
            return slotsInfo;
        } catch (e) {
            console.error(e.message);
            this.finalize();
        }
    }

    public searchTokensConnected(): void {
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

    public getTokensConnected(): number[] {
        return this.tokensConnected;
    }

    public getTokenConnectedInfo(token: number): Token {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            if (typeof this.tokensConnected[token] === 'undefined') throw new Error('Token index not exists');
            return new Token(this.tokensConnected[token], this.PKCS11.C_GetTokenInfo(this.getSlotbyToken(token)), this.getSlotbyToken(token));
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    public getTokenConnectedInfoResumen(token: number) {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            if (typeof this.tokensConnected[token] === 'undefined') throw new Error('Token index not exists');
            return new Token(this.tokensConnected[token], this.PKCS11.C_GetTokenInfo(this.getSlotbyToken(token)), this.getSlotbyToken(token)).getResumen();
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

    public getTokensConnectedInfoResumen(): Token[] {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            let tokens: any[] = [];

            for (let i=0; i < this.tokensConnected.length; i++) {
                tokens.push(this.getTokenConnectedInfoResumen(i));
            }
            return tokens;
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    private getSlotbyToken(token: number): Buffer {
        const slots: Buffer[] = this.getSlots();
        return slots[this.tokensConnected[token]];
    }

    public getSignMechanisms(token: number): MechanismInfo[] {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            let mechsInfo: MechanismInfo[] = [];
            var mechs: number[] = this.PKCS11.C_GetMechanismList(this.getSlotbyToken(token));

            for (let i=0; i < mechs.length; i++) {
                mechsInfo.push(new MechanismInfo(mechs[i],
                    this.PKCS11.C_GetMechanismInfo(this.getSlotbyToken(token), mechs[i])
                ));
            }
            return mechsInfo;
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    private initSession(token: number): pkcs11js.SessionInfo {
        try {
            if (!this.tokenReady) throw new Error('No tokens connected yet');
            this.session = this.PKCS11.C_OpenSession(this.getSlotbyToken(token), pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);
            return this.PKCS11.C_GetSessionInfo(this.session);
        } catch(e) {
            console.error(e);
            this.finalize();
        }
    }

    public login(token: number, password: string): boolean {
        try {
            this.initSession(token);
            if (!this.session) throw new Error('The token session is not already yet');
            this.PKCS11.C_Login(this.session, 1, password);
            this.tokenInUse = this.getTokenConnectedInfo(token);
            this.loggedIn = true;
            return true;
        } catch(e) {
            this.finalize();
            return false;
        }
    }

    public loginPersistent(token: number, password: string): boolean {
        try {
            this.initSession(token);
            if (!this.session) throw new Error('The token session is not already yet');
            this.PKCS11.C_Login(this.session, 1, password);
            this.tokenInUse = this.getTokenConnectedInfo(token);
            this.loggedIn = true;
            return true;
        } catch(e) {
            console.log(e);
            return false;
        }
    }
    
    public verifyTokenInUse(): boolean {
        try {
            if (!this.tokenInUse) throw new Error('No are a token in use');
            return this.tokenInUse.verifytoken(this);
        } catch(e) {
            this.finalize();
            return false;
        }
    }

    public verifyTokenInUsePersistent(): boolean {
        try {
            if (!this.tokenInUse) throw new Error('No are a token in use');
            return this.tokenInUse.verifytoken(this);
        } catch(e) {
            return false;
        }
    }

    public sign(algorithm: SignAlgorithm, data: Buffer): Signer {
        try {
            if(this.verifyTokenInUse()) {
                let signer = new Signer(algorithm, this.PKCS11, this.session);
                signer.sign(data);
                return signer;
            }
        } catch (e) {
            console.log(e);
            return null;
        }
    }

    public signBase64(algorithm: SignAlgorithm, data: string): Signer {
        try {
            if(this.verifyTokenInUse()) {
                let signer = new Signer(algorithm, this.PKCS11, this.session);
                signer.signBase64(data);
                return signer;
            }
        } catch (e) {
            console.log(e);
            return null;
        }
    }

    public validateCertificateExpiration(token: number): boolean {
        try {
            this.initSession(token);
            if (!this.session) throw new Error('The token session is not already yet');
            
            const x509Cert = new X509PublicKeyCert(this.PKCS11);
            x509Cert.getCertificate(this.session);

            var endDateBuffer: Buffer = x509Cert.CKA_END_DATE as Buffer;

            var endDate: Date = moment(endDateBuffer.toString(), 'YYYYMMDD').toDate();
            var today = new Date();

            if (today.getTime() > endDate.getTime()) {
                return false
            } else {
                return true;
            }
        } catch(e) {
            return false;
        }
    }

    public finalize(): boolean {
        try {
            this.logout();
            this.closeSession();
            this.PKCS11.C_Finalize();
            this.loggedIn = false;
            this.finalized = true;
            return true;
        } catch(e) {
            return false;
        }
    }

    public closeSession(): boolean {
        try {
            if (this.session) this.PKCS11.C_CloseSession(this.session);
            return true;
        } catch(e) {
            return false;
        }
    }

    public logout(): boolean {
        try {
            if (this.session) this.PKCS11.C_Logout(this.session);
            return true;
        } catch(e) {
            return false;
        }
    }

    public isLoggedIn(): boolean {
        return this.loggedIn;
    }

    public isFinalized(): boolean {
        return this.finalized;
    }
}