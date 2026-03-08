import { enroll, authenticate, getIdentity, clearIdentity } from './biokey.js'

const enrollBtn = document.getElementById('enroll-btn')
const authBtn = document.getElementById('auth-btn')
const resetBtn = document.getElementById('reset-btn')
const statusEl = document.getElementById('status')
const keyDisplay = document.getElementById('key-display')
const keyValue = document.getElementById('key-value')
const stateEl = document.getElementById('state')

function formatKey(hex) {
	return hex.match(/.{8}/g).join(' ')
}

function setStatus(type, message) {
	statusEl.className = `status ${type}`
	statusEl.textContent = message
	statusEl.style.display = 'block'
}

function hideStatus() {
	statusEl.style.display = 'none'
}

function updateUI() {
	const identity = getIdentity()
	if (identity) {
		stateEl.textContent = 'Enrolled'
		stateEl.className = 'state enrolled'
		keyDisplay.style.display = 'block'
		keyValue.textContent = formatKey(identity.publicKey)
		enrollBtn.disabled = true
		enrollBtn.textContent = 'Already Enrolled'
		authBtn.disabled = false
		resetBtn.style.display = 'inline-block'
	} else {
		stateEl.textContent = 'Not Enrolled'
		stateEl.className = 'state'
		keyDisplay.style.display = 'none'
		enrollBtn.disabled = false
		enrollBtn.textContent = 'Enroll Fingerprint'
		authBtn.disabled = true
		resetBtn.style.display = 'none'
	}
}

enrollBtn.addEventListener('click', async () => {
	enrollBtn.disabled = true
	enrollBtn.textContent = 'Waiting for fingerprint...'
	hideStatus()

	try {
		await enroll()
		setStatus('success', '✓ Enrolled. Your identity key is derived and stored.')
		updateUI()
	} catch (err) {
		setStatus('error', `✗ ${err.message}`)
		enrollBtn.disabled = false
		enrollBtn.textContent = 'Enroll Fingerprint'
	}
})

authBtn.addEventListener('click', async () => {
	authBtn.disabled = true
	authBtn.textContent = 'Waiting for fingerprint...'
	hideStatus()

	try {
		await authenticate()
		setStatus('success', '✓ Authenticated. Identity verified.')
	} catch (err) {
		setStatus('error', `✗ ${err.message}`)
	} finally {
		authBtn.disabled = false
		authBtn.textContent = 'Authenticate'
	}
})

resetBtn.addEventListener('click', () => {
	clearIdentity()
	hideStatus()
	updateUI()
})

updateUI()
