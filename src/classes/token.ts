import { Etoken } from './etoken';
import { TokenInfo } from 'pkcs11js';
import X509PublicKeyCert from './x509publickeycet';

export class Token {
    public slotId: number;
    public slot: Buffer;
    public label: string;
    public manufacturerID: string;
    public model: string;
    public serialNumber: string;
    public flags: number;
    public maxSessionCount: number;
    public sessionCount: number;
    public maxRwSessionCount: number;
    public rwSessionCount: number;
    public maxPinLen: number;
    public minPinLen: number;
    public hardwareVersion: any;
    public firmwareVersion: any;
    public utcTime: string;
    public totalPublicMemory: number;
    public freePublicMemory: number;
    public totalPrivateMemory: number;
    public freePrivateMemory: number;

    public x509Cert: X509PublicKeyCert;

    constructor(slotId: number, tokenInfo: TokenInfo, slot: Buffer = null) {
        this.slotId = slotId;
        this.slot = slot;
        this.label = tokenInfo.label.trim();
        this.manufacturerID = tokenInfo.manufacturerID.trim();
        this.model = tokenInfo.model.trim();
        this.serialNumber = tokenInfo.serialNumber.trim();
        this.flags = tokenInfo.flags;
        this.maxSessionCount = tokenInfo.maxSessionCount;
        this.sessionCount = tokenInfo.sessionCount;
        this.maxRwSessionCount = tokenInfo.maxRwSessionCount;
        this.rwSessionCount = tokenInfo.rwSessionCount;
        this.maxPinLen = tokenInfo.maxPinLen;
        this.minPinLen = tokenInfo.minPinLen;
        this.hardwareVersion = tokenInfo.hardwareVersion;
        this.firmwareVersion = tokenInfo.firmwareVersion;
        this.utcTime = tokenInfo.utcTime.trim();
        this.totalPublicMemory = tokenInfo.totalPublicMemory;
        this.freePublicMemory = tokenInfo.freePublicMemory;
        this.totalPrivateMemory = tokenInfo.totalPrivateMemory;
        this.freePrivateMemory = tokenInfo.freePrivateMemory;
    }
    
    public verifytoken(etoken: Etoken) {
        // Update the tokens lists
        etoken.searchTokensConnected();
        // Get the slots and position;
        const tokens = etoken.getTokensConnected();
        const tokenIndex = tokens.indexOf(this.slotId);
        // Verify if the token connected in the slot have the same Serial number of the token in use
        if (tokenIndex != -1) {
            const token = etoken.getTokenConnectedInfo(tokenIndex);
            if (this.serialNumber === token.serialNumber) {
                return true;
            }
        }
        return false;
    }

    public getResumen() {
        return {
            slotId: this.slotId,
            slot: this.slot,
            label: this.label,
            manufacturerID: this.manufacturerID,
            model: this.model,
            serialNumber: this.serialNumber,
            totalPublicMemory: this.totalPublicMemory,
            freePublicMemory: this.totalPublicMemory,
            totalPrivateMemory: this.totalPublicMemory,
            freePrivateMemory: this.totalPublicMemory
        };
    }

}