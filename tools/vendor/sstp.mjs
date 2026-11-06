// SPDX-License-Identifier: GPL-3.0-only
// SSTP/PPP/TCP implementation derived from cmliu/CF-Workers-CheckSocks5.
// Source: sx4tech/cm-Workers-CheckSocks5 _worker.js (2026-11-06 snapshot).
// Adaptation: Node.js TLS/Web Streams and DNS, no UI or Worker deployment required.
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import { lookup } from 'node:dns/promises';
const CONNECT_TIMEOUT_MS = 10000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function connect(address) {
  const socket = tls.connect({host:address.hostname, port:address.port,
    servername:address.hostname, rejectUnauthorized:true, minVersion:'TLSv1.2'});
  socket.setNoDelay(true);
  const opened = new Promise((resolve,reject)=>{
    socket.once('secureConnect',resolve); socket.once('error',reject);
  });
  const streams = Duplex.toWeb(socket);
  return {...streams, opened, close:()=>socket.destroy()};
}
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpBytes(length) {
	return crypto.getRandomValues(new Uint8Array(length));
}

function randomSstpUint16() {
	return readSstpUint16(randomSstpBytes(2));
}

function randomSstpUint32() {
	return readSstpUint32(randomSstpBytes(4));
}

function ipv4ToBytes(ip) {
	return new Uint8Array(String(ip || '').split('.').map(Number));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) {
		sum += readSstpUint16(bytes, index);
	}
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

function formatSstpHostHeader(hostname, port) {
	const host = stripIPv6Brackets(hostname);
	const displayHost = host.includes(':') ? `[${host}]` : host;
	return Number(port) === 443 ? displayHost : `${displayHost}:${port}`;
}

async function resolveSstpTargetIPv4(host) {
  if (isIPv4(host)) return host;
  return (await lookup(host, {family: 4})).address;
}

function createSstpClient(proxy) {
	let bufferedBytes = SSTP_EMPTY_BYTES;
	let pppIdentifier = 1;
	let socket = null;
	let reader = null;
	let writer = null;
	let serverHost = '';
	let serverPort = 443;

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return 数据转Uint8Array(value);
	};

	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatUint8(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};

	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = decoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}

			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatUint8(bufferedBytes, chunk) : chunk;
		}
	};

	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};

	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};

	const buildSstpControlPacket = (messageType, attributes = []) => {
		const attributesLength = attributes.reduce((size, attribute) => size + 4 + attribute.data.byteLength, 0);
		const packet = new Uint8Array(8 + attributesLength);
		const view = new DataView(packet.buffer);
		packet[0] = 0x10;
		packet[1] = 0x01;
		view.setUint16(2, (8 + attributesLength) | 0x8000);
		view.setUint16(4, messageType);
		view.setUint16(6, attributes.length);

		attributes.reduce((offset, attribute) => {
			packet[offset + 1] = attribute.id;
			view.setUint16(offset + 2, 4 + attribute.data.byteLength);
			packet.set(attribute.data, offset + 4);
			return offset + 4 + attribute.data.byteLength;
		}, 8);
		return packet;
	};

	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);

		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};

	const buildPapAuthenticateRequest = id => {
		if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
		const username = encoder.encode(proxy.username);
		const password = encoder.encode(proxy.password);
		if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');

		const papLength = 6 + username.byteLength + password.byteLength;
		const frame = new Uint8Array(2 + papLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, 0xc023);
		frame[2] = 1;
		frame[3] = id;
		view.setUint16(4, papLength);
		frame[6] = username.byteLength;
		frame.set(username, 7);
		frame[7 + username.byteLength] = password.byteLength;
		frame.set(password, 8 + username.byteLength);
		return frame;
	};

	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;

		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) {
			return {
				protocol,
				ipPacket: data.subarray(offset + 2)
			};
		}
		if (data.byteLength - offset < 6) return null;
		return {
			protocol,
			code: data[offset + 2],
			id: data[offset + 3],
			payload: data.subarray(offset + 6),
			rawPacket: data.subarray(offset)
		};
	};

	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({
				type,
				data: data.subarray(offset + 2, offset + length)
			});
			offset += length;
		}
		return options;
	};

	const connectToServer = async (hostname, port) => {
		serverHost = stripIPv6Brackets(hostname);
		serverPort = port;
		socket = connect({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();
	};

	const establishTunnel = async () => {
		const httpRequest = encoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${formatSstpHostHeader(serverHost, serverPort)}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);

		await withTimeout(writer.write(concatUint8(
			httpRequest,
			buildSstpControlPacket(0x0001, [{ id: 1, data: encapsulatedProtocol }]),
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let sstpAccepted = false;
		let localLcpAcked = false;
		let peerLcpAcked = false;
		let papRequired = false;
		let papSent = false;
		let papDone = false;
		let ipcpStarted = false;
		let ipcpFinished = false;
		let assignedIp = null;

		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPapAuthenticateRequest(pppIdentifier++))), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};

		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);

			if (packet.isControl) {
				if (!sstpAccepted && packet.body.byteLength >= 2 && readSstpUint16(packet.body) === 2) sstpAccepted = true;
				continue;
			}

			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}

					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					throw new Error('SSTP PAP authentication failed');
				}
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						assignedIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) assignedIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}

		if (!assignedIp) throw new Error('SSTP did not assign an IPv4 address');
		return assignedIp;
	};

	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }); } catch (e) { }
		try { reader?.releaseLock?.(); } catch (e) { }
		try { writer?.close?.().catch?.(() => { }); } catch (e) { }
		try { writer?.releaseLock?.(); } catch (e) { }
		try { socket?.close?.(); } catch (e) { }
	};

	return {
		connect: connectToServer,
		establishTunnel,
		readPacket,
		parsePPPFrame,
		close,
		get bufferedBytes() {
			return bufferedBytes;
		},
		get writer() {
			return writer;
		}
	};
}

function createTcpOverPppSession(sstp, sourceIp, destinationIp, destinationPort) {
	const sourcePort = 10000 + (randomSstpUint16() % 50000);
	const sourceAddress = ipv4ToBytes(sourceIp);
	const destinationAddress = ipv4ToBytes(destinationIp);

	let sequenceNumber = randomSstpUint32();
	let acknowledgementNumber = 0;

	const ipHeaderTemplate = new Uint8Array(20);
	ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
	ipHeaderTemplate.set(sourceAddress, 12);
	ipHeaderTemplate.set(destinationAddress, 16);

	const tcpPseudoHeader = new Uint8Array(1432);
	tcpPseudoHeader.set(sourceAddress);
	tcpPseudoHeader.set(destinationAddress, 4);
	tcpPseudoHeader[9] = 6;

	const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
		const bytes = 数据转Uint8Array(payload);
		const payloadLength = bytes.byteLength;
		const tcpLength = 20 + payloadLength;
		const ipLength = 20 + tcpLength;
		const sstpLength = 8 + ipLength;
		const frame = new Uint8Array(sstpLength);
		const view = new DataView(frame.buffer);

		frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
		frame.set(ipHeaderTemplate, 8);
		view.setUint16(10, ipLength);
		view.setUint16(12, randomSstpUint16());
		view.setUint16(18, internetChecksum(frame, 8, 20));

		view.setUint16(28, sourcePort);
		view.setUint16(30, destinationPort);
		view.setUint32(32, sequenceNumber);
		view.setUint32(36, acknowledgementNumber);
		frame[40] = 0x50;
		frame[41] = flags;
		view.setUint16(42, 65535);
		if (payloadLength) frame.set(bytes, 48);

		tcpPseudoHeader[10] = tcpLength >> 8;
		tcpPseudoHeader[11] = tcpLength & 0xff;
		tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
		view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
		return frame;
	};

	const matchIncomingIpPacket = ipPacket => {
		if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
		const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
		if (ipPacket.byteLength < ipHeaderLength + 20) return null;
		if (readSstpUint16(ipPacket, ipHeaderLength) !== destinationPort) return null;
		if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
		return {
			flags: ipPacket[ipHeaderLength + 13],
			sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
			payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
		};
	};

	const handshake = async () => {
		await withTimeout(sstp.writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;

		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await sstp.readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;

			const ppp = sstp.parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;

			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;

			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(sstp.writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			return;
		}
		throw new Error('TCP handshake through SSTP timed out');
	};

	return {
		buildTcpFrame,
		matchIncomingIpPacket,
		handshake,
		get sequenceNumber() {
			return sequenceNumber;
		},
		set sequenceNumber(value) {
			sequenceNumber = value >>> 0;
		},
		get acknowledgementNumber() {
			return acknowledgementNumber;
		},
		set acknowledgementNumber(value) {
			acknowledgementNumber = value >>> 0;
		}
	};
}

async function sstpConnect(proxy, targetHost, targetPort) {
	const sstp = createSstpClient(proxy);
	let closedSettled = false;
	let resolveClosed;
	let rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { sstp.close(); } catch (e) { }
		settleClosed(resolveClosed);
	};

	try {
		await sstp.connect(proxy.hostname, proxy.port);
		const targetIpPromise = resolveSstpTargetIPv4(targetHost);
		const [sourceIp, targetIp] = await Promise.all([
			sstp.establishTunnel(),
			targetIpPromise
		]);

		const tcp = createTcpOverPppSession(sstp, sourceIp, targetIp, targetPort);
		await tcp.handshake();

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [];
				let pendingLength = 0;

				const flush = () => {
					if (!pendingLength) return;
					const controller = streamController;
					if (!controller) throw new Error('SSTP readable stream is not ready');
					controller.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : concatUint8(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					sstp.writer.write(tcp.buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await sstp.readPacket(60000);
					if (packet.isControl) continue;

					const ppp = sstp.parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;

					const incoming = tcp.matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							tcp.acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						tcp.acknowledgementNumber = (tcp.acknowledgementNumber + 1) >>> 0;
						sstp.writer.write(tcp.buildTcpFrame(0x11)).catch(() => { });
						try { streamController?.close?.(); } catch (e) { }
						close();
						return;
					}

					if (sstp.bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				try { streamController?.error?.(error); } catch (e) { }
				settleClosed(rejectClosed, error);
				try { sstp.close(); } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = 数据转Uint8Array(chunk);
				if (!bytes.byteLength) return;

				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await sstp.writer.write(tcp.buildTcpFrame(0x18, bytes));
					tcp.sequenceNumber = (tcp.sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}

				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(tcp.buildTcpFrame(0x18, segment));
					tcp.sequenceNumber = (tcp.sequenceNumber + segment.byteLength) >>> 0;
				}
				await sstp.writer.write(concatUint8(...frames));
			},
			close() {
				return sstp.writer.write(tcp.buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(message)), timeoutMs);
			})
		]);
	} finally {
		clearTimeout(timer);
	}
}

function 数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function concatUint8(...chunks) {
	const arrays = chunks.filter(Boolean).map(数据转Uint8Array);
	const length = arrays.reduce((sum, chunk) => sum + chunk.byteLength, 0);
	const output = new Uint8Array(length);
	let offset = 0;
	for (const chunk of arrays) {
		output.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return output;
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => {
		if (!/^\d{1,3}$/.test(part)) return false;
		const num = Number(part);
		return num >= 0 && num <= 255;
	});
}


export { sstpConnect, withTimeout };
