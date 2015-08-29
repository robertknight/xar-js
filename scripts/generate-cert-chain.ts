/// <reference path="../typings/tsd.d.ts" />

// this script generates a certificate chain consisting
// of a self-signed root certificate, an intermediate cert and
// a leaf cert using OpenSSL

import * as Q from 'q';
import * as fs from 'fs';

var exec = require('child-process-promise').exec;

enum CertType {
	X509Cert,
	CertRequest
}

function generateCert(certFile: string, keyFile: string, subject: string, type: CertType) {
	let cmd = ['openssl', 'req', '-new', '-nodes', '-out', certFile,
	           '-keyout', keyFile, '-subj', `/CN=${subject}`, '-newkey', 'rsa:2048', '-sha1'];
  if (type === CertType.X509Cert) {
		cmd.push('-x509');
	}
	return exec(cmd.join(' '));
}

interface SigningOpts {
	enableCAUsage?: boolean;
}

function signCert(requestName: string,
                  childCert: string,
                  parentCert: string,
                  parentCertKey: string,
                  serial: string,
								  opts: SigningOpts = {}) {
	let cmd = ['openssl', 'x509', '-req', '-in', requestName, '-CAkey', parentCertKey,
	           '-CA', parentCert, '-days', '360', '-set_serial', serial, '-sha1',
						 '-out', childCert];
	if (opts.enableCAUsage) {
		let extFile = '/tmp/cert-extensions.cfg';
		fs.writeFileSync(extFile, `
[v3_extensions]
basicConstraints=CA:true
`);
    cmd.push(...['-extfile', extFile, '-extensions', 'v3_extensions']);
	}
	return exec(cmd.join(' '));
}

function verifyCert(cert: string, intermediates: string[], roots: string[]) {
	let cmd = ['openssl', 'verify'];
	for (let intermediate of intermediates) {
		cmd.push(...['-untrusted', intermediate]);
	}
	for (let root of roots) {
		cmd.push(...['-CAfile', root]);
	}
	cmd.push(cert);
	return exec(cmd.join(' '));
}

let rootName = 'root.crt';
let rootKeyName = 'root.key';

let intermediateReqName = 'intermediate.req';
let intermediateName = 'intermediate.crt';
let intermediateKeyName = 'intermediate.key';

let leafName = 'leaf.crt';
let leafReqName = 'leaf.req';
let leafKeyName = 'leaf.key';

let rootGenerated = generateCert(rootName, rootKeyName, 'TestRoot', CertType.X509Cert);
let intermediateGenerated = generateCert(intermediateReqName, intermediateKeyName, 'TestIntermediate',
  CertType.CertRequest);
let leafGenerated = generateCert(leafReqName, leafKeyName, 'TestLeaf', CertType.CertRequest);

Q.all([rootGenerated, intermediateGenerated, leafGenerated]).then(() => {
	return signCert(intermediateReqName, intermediateName, rootName, rootKeyName, '1234567', {
		enableCAUsage: true
	});
}).then(() => {
	return signCert(leafReqName, leafName, intermediateName, intermediateKeyName, '8901234');
}).then(() => {
	return verifyCert(leafName, [intermediateName], [rootName]);
}).then(result => {
	if (result.exitCode !== 0 || result.stdout.indexOf('OK') === -1 || result.stdout.indexOf('error') !== -1) {
		throw new Error('Failed to verify generated certificates');
	}
});
