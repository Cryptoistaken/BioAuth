import { useState, useEffect, useCallback, useRef } from 'react'
import { BioKeyClient } from 'biokey-js'

export function useBioKey(options = {}) {
	const clientRef = useRef(null)

	if (!clientRef.current) {
		clientRef.current = new BioKeyClient(options)
	}

	const client = clientRef.current

	const [identity, setIdentity] = useState(() => client.getIdentity())
	const [status, setStatus] = useState('idle')
	const [error, setError] = useState(null)

	useEffect(() => {
		setIdentity(client.getIdentity())
	}, [])

	const enroll = useCallback(async (userId) => {
		setStatus('enrolling')
		setError(null)
		try {
			const result = await client.enroll(userId)
			setIdentity(result)
			setStatus('enrolled')
			return result
		} catch (err) {
			setError(err.message)
			setStatus('error')
			throw err
		}
	}, [client])

	const authenticate = useCallback(async (userId) => {
		setStatus('authenticating')
		setError(null)
		try {
			const result = await client.authenticate(userId)
			setStatus('authenticated')
			return result
		} catch (err) {
			setError(err.message)
			setStatus('error')
			throw err
		}
	}, [client])

	const reset = useCallback(() => {
		client.clearIdentity()
		setIdentity(null)
		setStatus('idle')
		setError(null)
	}, [client])

	return {
		identity,
		status,
		error,
		isEnrolled: !!identity,
		isLoading: status === 'enrolling' || status === 'authenticating',
		enroll,
		authenticate,
		reset
	}
}
