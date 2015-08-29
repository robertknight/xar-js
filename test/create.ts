/// <reference path="../typings/tsd.d.ts" />

import {expect} from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import {generateCertificateChain} from '../scripts/generate-cert-chain';

import {XarArchive} from '../src/lib';
import {walk, FileReader, FileWriter} from '../src/util';

describe('archive creation', () => {
  it('should create a xar archive', () => {
    const extensionDir = walk('./test/testextension.safariextension');

    const archive = new XarArchive();
    const writer = new FileWriter('test-create.safariextz');
    archive.addFile(extensionDir);
    archive.generate(writer, path => new FileReader('./test/' + path));

    // read the archive and verify that it at least returns
    // a non-empty table of contents
    const readArchive = new XarArchive();
    readArchive.open(new FileReader('test-create.safariextz'));
    let toc = readArchive.tableOfContentsXML();
    expect(toc.length).to.be.greaterThan(0);
  });
});

describe('archive signing', () => {
  let tmpDir = os.tmpdir();
  let leafPrefix = `${tmpDir}/leaf`;
  let intermediatePrefix = `${tmpDir}/intermediate`;
  let rootPrefix = `${tmpDir}/root`;

  before(() => {
    return generateCertificateChain(leafPrefix, intermediatePrefix, rootPrefix);
  });

  it('should add signature data to TOC', () => {
    const extensionDir = walk('./test/testextension.safariextension');
    const archive = new XarArchive();
    const writer = new FileWriter('test-sign.safariextz');
    archive.addFile(extensionDir);

    let leafCert = fs.readFileSync(`${leafPrefix}.crt`, 'utf-8');
    let intermediate = fs.readFileSync(`${intermediatePrefix}.crt`, 'utf-8');
    let privateKey = fs.readFileSync(`${leafPrefix}.key`, 'utf-8');
    archive.setCertificates({
      cert: leafCert,
      privateKey,
      additionalCerts: [intermediate]
    });

    archive.generate(writer, path => new FileReader('./test/' + path));

    const readArchive = new XarArchive();
    readArchive.open(new FileReader('test-sign.safariextz'));
    let toc = readArchive.tableOfContentsXML();
    expect(toc.indexOf('<signature')).to.not.equal(-1);
  });
});
