/// <reference path="../typings/tsd.d.ts" />

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as xml2js from 'xml2js';

import { generateCertificateChain } from '../scripts/generate-cert-chain';
import { XarArchive } from '../src/lib';
import { FileReader, FileWriter } from '../src/io';
import { walk } from '../src/util';

function parseXML(content: string) {
  let xml: Object;
  xml2js.parseString(content, { async: false },(err, result) => {
    if (err) {
      throw err;
    }
    xml = result;
  });
  return xml;
}

function fixturePath(name: string) {
  return './test/fixtures/' + name;
}

describe('archive creation',() => {
  it('should create a xar archive',() => {
    const extensionDir = walk(fixturePath('testextension.safariextension'));
    const archivePath = path.join(os.tmpdir(), 'test-create.safariextz');
    const archive = new XarArchive();
    const writer = new FileWriter(archivePath);
    archive.addFile(extensionDir);
    archive.generate(writer, path => new FileReader(path));

    // read the archive and verify that it at least returns
    // a non-empty table of contents
    const readArchive = new XarArchive();
    readArchive.open(new FileReader(archivePath));
    let toc = readArchive.tableOfContentsXML();
    expect(toc.length).to.be.greaterThan(0);
  });

  it('should create a xar archive with an empty file',() => {
    const emptyFile = walk(fixturePath('empty'));
    const archivePath = path.join(os.tmpdir(), 'test-empty.xar');
    const writer = new FileWriter(archivePath);
    const archive = new XarArchive();
    archive.addFile(emptyFile);
    archive.generate(writer, path => new FileReader(path));
    const readArchive = new XarArchive();
    readArchive.open(new FileReader(archivePath));
    let toc = readArchive.tableOfContentsXML();
  });
});

function isValidBase64(content: string) {
  return content.match(/^[0-9a-zA-Z/+=]*$/) !== null;
}

describe('archive signing',() => {
  let tmpDir = os.tmpdir();
  let leafPrefix = `${tmpDir}/leaf`;
  let intermediatePrefix = `${tmpDir}/intermediate`;
  let rootPrefix = `${tmpDir}/root`;

  before(() => {
    return generateCertificateChain(leafPrefix, intermediatePrefix, rootPrefix);
  });

  it('should add signature data to TOC',() => {
    const extensionDir = walk(fixturePath('testextension.safariextension'));
    const archivePath = path.join(os.tmpdir(), 'test-sign.safariextz');
    const archive = new XarArchive();
    const writer = new FileWriter(archivePath);
    archive.addFile(extensionDir);

    // add extra content before and after cert to verify that
    // this is ignored
    let leafCert = 'content before cert\n' +
      fs.readFileSync(`${leafPrefix}.crt`, 'utf-8') +
      '\ncontent after cert';

    let intermediate = fs.readFileSync(`${intermediatePrefix}.crt`, 'utf-8');
    let privateKey = fs.readFileSync(`${leafPrefix}.key`, 'utf-8');
    archive.setCertificates({
      cert: leafCert,
      privateKey,
      additionalCerts: [intermediate]
    });

    archive.generate(writer, path => new FileReader(path));

    // read back archive, check that signature data appears in
    // XML header
    const readArchive = new XarArchive();
    readArchive.open(new FileReader(archivePath));
    let tocXMLTree: any = parseXML(readArchive.tableOfContentsXML());
    let signature = tocXMLTree.xar.toc[0].signature[0];
    expect(signature).to.be.ok;
    let certs: string[] = signature.KeyInfo[0].X509Data[0].X509Certificate
      .map((cert: string) => cert.replace(/\n/gm, ''));
    expect(certs).to.be.ok;
    expect(certs.length).to.equal(2);
    certs.forEach(cert => expect(isValidBase64(cert)).to.be.true);
  });
});
