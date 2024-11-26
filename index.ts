import forge from 'node-forge';
import { Buffer } from 'node:buffer';
import { getCurve25519PublicKey, pairVerify } from './utils';

interface Headers {
  [key: string]: string;
}

// Parse RTSP request into components
function parseRTSPRequest(data: string) {
  const lines = data.split('\r\n');
  const [method, path] = lines[0].split(' ');

  // Parse headers
  const headers = lines.slice(1).reduce((acc: Headers, line) => {
    const [key, value] = line.split(': ');
    if (key && value) {
      acc[key.toLowerCase()] = value.trim();
    }
    return acc;
  }, {});

  // Get body if present
  const bodyStart = data.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? data.slice(bodyStart + 4) : '';

  return { method, path, headers, body };
}

// Create RTSP response
function createRTSPResponse(statusCode: number, headers: Headers, body?: string | Uint8Array | Buffer) {
  const statusText = statusCode === 200 ? 'OK' : 'Bad Request';
  let response = `RTSP/1.0 ${statusCode} ${statusText}\r\n`;

  // Add standard headers
  headers = {
    'Server': 'AirTunes/366.0',
    ...headers
  };

  // Add Content-Length if body exists
  if (body) {
    headers['Content-Length'] = Buffer.isBuffer(body) ? body.length.toString() : Buffer.byteLength(body).toString();
  }

  // Add headers to response
  for (const [key, value] of Object.entries(headers)) {
    response += `${key}: ${value}\r\n`;
  }

  response += '\r\n';

  // Convert response to Buffer and append body if it exists
  const responseBuffer = Buffer.from(response);
  if (body) {
    return Buffer.concat([responseBuffer, Buffer.isBuffer(body) ? body : Buffer.from(body)]);
  } else {
    return responseBuffer;
  }
}

// Generate device info response
function getDeviceInfoResponse(cseq: string) {
  const deviceInfo = {
    PTPInfo: 'OpenAVNU ArtAndLogic-aPTP-changes 1.0',
    build: '17.0',
    deviceID: '00:05:CD:D4:42:38',
    features: 496155769145856,
    firmwareBuildDate: 'Jan 30 2019',
    firmwareRevision: '1.505.130',
    keepAliveLowPower: true,
    keepAliveSendStatsAsBody: true,
    manufacturer: 'Sound United',
    model: 'AVR-X3500H',
    name: 'AirPlay-Test',
    nameIsFactoryDefault: false,
    pi: '650c20ee-842c-4c01-80ed-22b7fb239881',
    protocolVersion: '1.1',
    sdk: 'AirPlay;2.0.2',
    sourceVersion: '366.0',
    statusFlags: 4,
    txtAirPlay: Buffer.from('BWFjbD0wGmRldmljZWlkPTAwOjA1OkNEOkQ0OjQyOjk2G2ZlYXR1cmVzPTB4NDQ1RjhBMDAsMHgxQzM0MAdyc2Y9MHgwEGZ2PXAyMC4xLjUwNS4xMzAJZmxhZ3M9MHg0EG1vZGVsPUFWUi1YMzUwMEgZbWFudWZhY3R1cmVyPVNvdW5kIFVuaXRlZBtzZXJpYWxOdW1iZXI9QkJXMzYxODEyMTIzNjQNcHJvdG92ZXJzPTEuMQ1zcmN2ZXJzPTM2Ni4wJ3BpPTY1MGMyMGVlLTg0MmMtNGMwMS04MGVkLTIyYjdmYjIzOTg4MShnaWQ9NjUwYzIwZWUtODQyYy00YzAxLTgwZWQtMjJiN2ZiMjM5ODgxBmdjZ2w9MENwaz0wYWNkN2Q2MWIyODRjMGFmNzFjN2VmNGY3ZWE2NDRkZGRlYzIzOGVmMjdjM2MwYWQzZDVkM2JiOWM4YjMxZThm', 'base64')
  };

  const plistBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
${Object.entries(deviceInfo).map(([key, value]) => {
    if (typeof value === 'boolean') {
      return `    <key>${key}</key>\n    <${value}/>`;
    } else if (value instanceof Buffer) {
      return `    <key>${key}</key>\n    <data>\n    ${value.toString('base64')}\n    </data>`;
    } else {
      return `    <key>${key}</key>\n    <string>${value}</string>`;
    }
  }).join('\n')}
</dict>
</plist>`;

  return createRTSPResponse(200, {
    'Content-Type': 'application/x-apple-binary-plist',
    'CSeq': cseq
  }, plistBody);
}

// Initialize server
const keyPair = forge.pki.ed25519.generateKeyPair();

function toArrayBuffer(buffer: Buffer) {
  const arrayBuffer = new ArrayBuffer(buffer.length);
  const view = new Uint8Array(arrayBuffer);
  for (let i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  return arrayBuffer;
}

Bun.listen({
  hostname: '0.0.0.0',
  port: 7000,
  socket: {
    async data(socket, data) {
      const request = parseRTSPRequest(data.toString());
      console.log(`${request.method} ${request.path}`);

      try {
        if (request.method === 'GET' && request.path === '/info') {
          socket.write(getDeviceInfoResponse(request.headers['cseq']));
        } else if (request.method === 'POST' && request.path === '/pair-setup') {
          const key = getCurve25519PublicKey();
          const response = createRTSPResponse(200, {
            'CSeq': request.headers['cseq'],
          }, Buffer.from(key.buffer).toString('hex'));
          console.log(Buffer.from(response).toString());
          socket.write(response);
        } else if (request.method === 'POST' && request.path === '/pair-verify') {
          const response = await pairVerify(Buffer.from(request.body));
          const rr = createRTSPResponse(200, {
            'CSeq': request.headers['cseq']
          }, response.toString('hex'));
          console.log(Buffer.from(rr).toString());
          socket.write(rr);
        } else {
          console.log('Bad request', request.path);
          socket.write(createRTSPResponse(400, {
            'CSeq': request.headers['cseq']
          }));
        }
      } catch (error) {
        console.error('Error handling request:', error);
        socket.write(createRTSPResponse(500, {
          'CSeq': request.headers['cseq']
        }));
      }
    },
    open(socket) {
      console.log('Socket opened');
    },
    close(socket) {
      console.log('Socket closed');
    },
  }
});