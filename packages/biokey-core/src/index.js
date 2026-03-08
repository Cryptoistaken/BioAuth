import { enroll } from './enroll.js'
import { authenticate } from './authenticate.js'
import { bufToHex, hexToBuf, deriveKey, extractPRFOutput, isPRFSupported, PRF_SALT } from './derive.js'

export class BioKey {
	constructor(options = {}) {
		this.rpId = options.rpId ?? location.hostname
		this.rpName = options.rpName ?? 'BioKey'
	}

	// Returns { publicKey, credentialId, enrolledAt, method: 'prf' | 'rawid' }
	async enroll() {
		return enroll(this.rpId, this.rpName)
	}

	// Returns { verified, publicKey, method: 'prf' | 'rawid' }
	async authenticate(identity) {
		return authenticate(identity, this.rpId)
	}
}

export {
	enroll,
	authenticate,
	bufToHex,
	hexToBuf,
	deriveKey,
	extractPRFOutput,
	isPRFSupported,
	PRF_SALT
}
