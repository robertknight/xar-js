// this script generates a certificate chain consisting
// of a self-signed root certificate, an intermediate cert and
// a leaf cert using OpenSSL

import * as Q from 'q';
import * as fs from 'fs';
import * as path from 'path';

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
    // mark the certificate as being usable for signing other certificates.
    // See https://www.openssl.org/docs/manmaster/apps/req.html and
    // http://stackoverflow.com/a/5795827/434243
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

export function generateCertificateChain(leafPrefix: string, intermediatePrefix: string, rootPrefix: string) {

  let rootName = rootPrefix + '.crt';
  let rootKeyName = rootPrefix + '.key';

  let intermediateReqName = intermediatePrefix + '.req';
  let intermediateName = intermediatePrefix + '.crt';
  let intermediateKeyName = intermediatePrefix + '.key';

  let leafName = leafPrefix + '.crt';
  let leafReqName = leafPrefix + '.req';
  let leafKeyName = leafPrefix + '.key';

  let rootGenerated = generateCert(rootName, rootKeyName, 'TestRoot', CertType.X509Cert);
  let intermediateGenerated = generateCert(intermediateReqName, intermediateKeyName, 'TestIntermediate',
    CertType.CertRequest);
  let leafGenerated = generateCert(leafReqName, leafKeyName, 'TestLeaf', CertType.CertRequest);

  return Q.all([rootGenerated, intermediateGenerated, leafGenerated]).then(() => {
    return signCert(intermediateReqName, intermediateName, rootName, rootKeyName, '1234567', {
      enableCAUsage: true
    });
  }).then(() => {
    return signCert(leafReqName, leafName, intermediateName, intermediateKeyName, '8901234');
  }).then(() => {
    return verifyCert(leafName, [intermediateName], [rootName]);
  }).then(result => {
    // if verification is successful openssl will output 'leaf.crt: OK'.
    // If verification fails, the command may exit with a zero status code
    // but an error message via stdout in some circumstances
    // (eg. if the intermediate cert does not specify 'basicConstraints=CA:true'
    //  in x509 v3 properties)
    if (result.childProcess.exitCode !== 0 || result.stdout.indexOf('OK') === -1 || result.stdout.indexOf('error') !== -1) {
      throw new Error('Failed to verify generated certificates: ' + result.stdout);
    }
  });
}

if (require.main === module) {
  let[rootPrefix, intermediatePrefix, leafPrefix] = process.argv.slice(2);
  if (!rootPrefix || !intermediatePrefix || !leafPrefix) {
    let scriptName = path.basename(process.argv[1]);
    console.log(`Usage: %s <root cert prefix> <intermediate cert prefix> <leaf cert prefix>

Generates an SSL certificate chain for testing purposes, consisting
of a self-signed root certificate and intermediate and leaf certificats.`, scriptName);
    process.exit(1);
  }
  generateCertificateChain(leafPrefix, intermediatePrefix, rootPrefix).done();
}
