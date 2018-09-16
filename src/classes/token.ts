import { Etoken } from './etoken';

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

    constructor(slotId: number, token_info: any, slot: Buffer = null) {
        this.slotId = slotId;
        this.slot = slot;
        this.label = token_info.label.trim();
        this.manufacturerID = token_info.manufacturerID.trim();
        this.model = token_info.model.trim();
        this.serialNumber = token_info.serialNumber.trim();
        this.flags = token_info.flags;
        this.maxSessionCount = token_info.maxSessionCount;
        this.sessionCount = token_info.sessionCount;
        this.maxRwSessionCount = token_info.maxRwSessionCount;
        this.rwSessionCount = token_info.rwSessionCount;
        this.maxPinLen = token_info.maxPinLen;
        this.minPinLen = token_info.minPinLen;
        this.hardwareVersion = token_info.hardwareVersion;
        this.firmwareVersion = token_info.firmwareVersion;
        this.utcTime = token_info.utcTime.trim();
        this.totalPublicMemory = token_info.totalPublicMemory;
        this.freePublicMemory = token_info.freePublicMemory;
        this.totalPrivateMemory = token_info.totalPrivateMemory;
        this.freePrivateMemory = token_info.freePrivateMemory
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

}