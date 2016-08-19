/// <reference path="../typings/tsd.d.ts" />

import * as xml2js from 'xml2js';
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { createHash, createSign } from 'crypto';

import { Reader, Writer } from './io';

var ctype: any = require('ctype');

// use pako for synchronous zlib compression/decompression
// rather than Node's zlib.{inflateSync, deflateSync} for
// compatibility with Node <= 0.10.x
var pako = require('pako');

export enum FileType {
  File,
  Directory
}

export enum Encoding {
  // the xar file format supports several encodings, but
  // only 'gzip' is supported.

  // Note that despite being called 'gzip', the compressed
  // file data is not actually in gzip format but is actually just
  // compressed with deflate.
  // In other words, the compressed data does not have a gzip header.
  Gzip
}

/** Base interface for entries in a xar archive.
 * Two types of entries are supported, files represented
 * by XarCompressedFile and directories, represented by
 * XarDirectory
 */
export interface XarFile {
  /** ID of the file entry. This must be unique within an archive. */
  id?: number;
  /** Filename of the file entry, not including the path. */
  name: string;
  type: FileType;
  /**
    * The full path of the source for this entry, used only when
    * generating archives.
    */
  srcPath?: string;
}

export interface XarFileData {
  /** The checksum of the compressed file data in the archive. */
  archivedChecksum?: string;
  /** The checksum of the uncompressed file */
  extractedChecksum?: string;

  /** The offset of the file's data within the heap */
  offset?: number;
  /** The decompressed file size */
  size: number;
  /** The size of the compressed file within the heap */
  length?: number;

  // Attributes which are set once the data has been
  // read and compressed
  encoding?: Encoding;

  /** The compressed data for the entry. The encoding is specified
   * by the 'encoding' property.
   */
  data?: Buffer;
}

export interface XarCompressedFile extends XarFile {
  data: XarFileData;
}

export interface XarDirectory extends XarFile {
  /** Files or directories within this directory. */
  children: XarFile[];
}

function deflateSync(buf: Buffer) {
  return new Buffer(pako.deflate(buf));
}

function inflateSync(buf: Buffer) {
  return new Buffer(pako.inflate(buf));
}

function buildXML(obj: Object) {
  let builder = new xml2js.Builder({
    xmldec: {
      version: '1.0',
      encoding: 'UTF-8'
    }
  });
  return builder.buildObject(obj);
}

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

// a wrapper around a Writer which tracks the number
// of bytes written
class TrackingWriter implements Writer {
  private dest: Writer;

  bytesWritten: number;

  constructor(dest: Writer) {
    this.dest = dest;
    this.bytesWritten = 0;
  }

  write(data: Buffer) {
    this.dest.write(data);
    this.bytesWritten += data.length;
  }
}

// generates the table of contents entry for a file
// or directory entry
function xarFileTOCEntry(file: XarFile): Object {
  assert(file.id);
  assert(file.name);
  assert(file.srcPath);

  let entry: any = {
    $: {
      id: file.id
    },
    name: file.name,
    type: file.type === FileType.Directory ? 'directory' : 'file'
  };
  if (file.type === FileType.Directory) {
    entry.file = (<XarDirectory>file).children.map(xarFileTOCEntry);
  } else {
    assert(file.type === FileType.File);

    let compressedFile = <XarCompressedFile>file;
    if (typeof compressedFile.data.offset !== 'number') {
      throw new Error(`Heap data missing for ${file.name}`);
    }
    if (!compressedFile.data.archivedChecksum) {
      throw new Error(`Archived checksum missing for ${file.name}`);
    }
    if (!compressedFile.data.extractedChecksum) {
      throw new Error(`Extracted checksum missing for ${file.name}`);
    }

    entry.data = {
      offset: compressedFile.data.offset,
      size: compressedFile.data.size,
      length: compressedFile.data.length,
      ['archived-checksum']: {
        $: {
          style: 'sha1'
        },
        _: compressedFile.data.archivedChecksum
      },
      ['extracted-checksum']: {
        $: {
          style: 'sha1'
        },
        _: compressedFile.data.extractedChecksum
      },
      encoding: {
        $: {
          style: 'application/x-gzip'
        }
      }
    }
  }
  return entry;
}

enum DigestAlgorithm {
  // the xar file format supports several digest algorithms.
  // Only SHA-1 is currently supported by xar-js
  SHA1
}

function digestSize(algo: DigestAlgorithm) {
  assert(algo === DigestAlgorithm.SHA1);
  return 20;
}

function shasum(data: Buffer): string {
  let hasher = createHash('sha1');
  hasher.update(data);
  return hasher.digest('hex');
}

function walkFileTree(file: XarFile, visit: (path: string, file: XarFile) => any, dirPath: string = '') {
  visit(file.srcPath, file);
  if (file.type === FileType.Directory) {
    (<XarDirectory>file).children.forEach(child => {
      walkFileTree(child, visit, file.srcPath);
    });
  }
}

/** Specifies the certificates and private key used
 * to sign the archive.
 */
export interface SignatureResources {
  /** The PEM encoded leaf certificate, corresponding to
   * the private key.
   */
  cert: string;
  /** The PEM encoded private key for @p cert */
  privateKey: string;
  /*
   * Additional certificates to include in the archive.
   * These are the intermediate certificates between @p cert
   * and the root certificate which is already trusted by the
   * system.
   *
   * Note that the order in which the certificates are specified
   * is important when building Safari extensions. The intermediate
   * certificate used to sign the leaf certificate must come first,
   * followed by other certificates in the order they occur in
   * the verification chain.
   */
  additionalCerts: string[];
}

// minimum header size. If the archive uses a non-standard
// checksum algorithm then it may be larger in order to store
// the name of the algorithm
const XAR_HEADER_SIZE = 28;
const XAR_MAGIC = 0x78617221; // "xar!"

// checksum algorithms
const XAR_CHECKSUM_SHA1 = 1;

// signature algorithms
const RSA_SIGNATURE_SIZE = 256;

interface XarHeader {
  size: number;
  version: number;
  tocLengthCompressed: number;
  tocLengthUncompressed: number;
  checksumAlgorithm: number;
}

// Extracts the contents of a Base64-encoded section of
// a PEM file.
//
// Returns the lines between the section demarcated by
// 'BEGIN <sectionType> ... END <sectionType>' in 'cert'
function extractPEMSection(cert: string, sectionType: string) {
  let inSection = false;
  return cert.split('\n').reduce((sectionLines, line) => {
    if (inSection) {
      if (line.indexOf('----END ' + sectionType) !== -1) {
        inSection = false;
      } else {
        sectionLines.push(line);
      }
    } else if (line.indexOf('----BEGIN ' + sectionType) !== -1) {
      inSection = true;
    }
    return sectionLines;
  }, []).join('\n');
}

function extractCertSection(pemFile: string) {
  let cert = extractPEMSection(pemFile, 'CERTIFICATE')
  if (cert.length === 0) {
    throw new Error(`Missing expected BEGIN CERTIFICATE ... END CERTIFICATE section in '${pemFile}'`);
  }
  return cert;
}

// Buffer.equals() is available in Node >= 0.11.
// This is provided for compatibility with Node 0.10
function bufferEquals(a: Buffer, b: Buffer) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/** Class for reading and writing xar archives.
 *
 * To read an existing archive, create an instance and call
 * open() passing in a Reader implementation to read archive data from.
 *
 * To generate an archive, create an instance, call addFile() to add
 * files to the archive and generate() to output the archive to
 * a Writer.
 */
export class XarArchive {
  private ctypeParser: any;
  private checksumAlgo: DigestAlgorithm;
  private files: XarFile[];
  private signatureResources: SignatureResources;
  private reader: Reader;

  constructor() {
    this.files = [];
    this.checksumAlgo = DigestAlgorithm.SHA1;

    this.ctypeParser = new ctype.Parser({ endian: 'big' });
    this.ctypeParser.typedef('xar_header', [
      { magic: { type: 'uint32_t' } },
      { size: { type: 'uint16_t' } },
      { version: { type: 'uint16_t' } },
      { toc_length_compressed: { type: 'uint64_t' } },
      { toc_length_uncompressed: { type: 'uint64_t' } },
      { cksum_alg: { type: 'uint32_t' } }
    ]);
  }

  /** Open an existing archive */
  open(reader: Reader) {
    this.files = [];
    this.reader = reader;
  }

  /** Return the table of contents from the current archive as an XML string */
  tableOfContentsXML() {
    let header = this.readHeader();
    let compressedTOC = this.reader.read(header.size, header.tocLengthCompressed);

    // verify checksum
    if (header.checksumAlgorithm !== XAR_CHECKSUM_SHA1) {
      throw new Error(`Unsupported table of contents checksum algorithm ${header.checksumAlgorithm}`);
    }
    let checksumSize = digestSize(DigestAlgorithm.SHA1);
    let expectedChecksum = this.reader.read(header.size + header.tocLengthCompressed, checksumSize);
    let actualChecksum = createHash('sha1').update(compressedTOC).digest();
    if (!bufferEquals(actualChecksum, expectedChecksum)) {
      throw new Error('Actual table of contents checksum does not match expected checksum');
    }

    // uncompress table of contents
    let tocData = inflateSync(compressedTOC);
    if (tocData.length !== header.tocLengthUncompressed) {
      throw new Error(`Table of contents length (${tocData.length}) does not match size specified in header (${header.tocLengthUncompressed})`);
    }
    return tocData.toString('utf-8');
  }

  /** Add the metadata for a new file or directory tree to
   * the archive. To create a XarFile instance from a file on disk,
   * see the walk() function in the util module.
   *
   * The file's data is not actually read until generate() is called.
   */
  addFile(file: XarFile) {
    assert(file);
    this.files.push(file);
  }

  /** Sets the certificates used to sign the generated archive. */
  setCertificates(opts: SignatureResources) {
    this.signatureResources = opts;
  }

  /** Generate the xar archive. Reads the data for the files that
   * have been added to the archive using @p fileDataProvider
   * and writes the result to @p writer.
   */
  generate(writer: Writer, fileDataProvider: (path: string) => Reader) {
    // update heap size/offset entries for files
    let heapSize = digestSize(this.checksumAlgo);

    // assign IDs to all files
    let maxID = 0;
    this.files.forEach(file => {
      walkFileTree(file,(_, file) => {
        maxID = file.id ? Math.max(file.id, maxID) : maxID;
      });
    });

    // if there is a signature, increment the heap size
    // by the signature size
    if (this.signatureResources) {
      heapSize += RSA_SIGNATURE_SIZE;
    }

    // create list of files to compress
    let fileList: XarCompressedFile[] = [];
    let paths: string[] = [];
    this.files.forEach(file => {
      walkFileTree(file,(path, file) => {
        if (!file.id) {
          ++maxID;
          file.id = maxID;
        }
        if (file.type === FileType.File) {
          fileList.push(<XarCompressedFile>file);
          paths.push(path);
        }
      });
    });
    fileList.sort((a, b) => a.id - b.id);

    fileList.forEach((file, index) => {
      if (typeof file.data.offset !== 'number') {
        // compress file data, compute checksums and storage
        // location within heap
        let reader = fileDataProvider(paths[index]);
        let sourceData = reader.read(0, file.data.size);
        assert(sourceData.length === file.data.size);
        file.data.data = deflateSync(sourceData);
        file.data.length = file.data.data.length;
        file.data.offset = heapSize;
        file.data.archivedChecksum = shasum(file.data.data);
        file.data.extractedChecksum = shasum(sourceData);
        heapSize += file.data.length;
      }
    });

    let tocXML = this.generateTOC();
    let tocXMLBuffer = new Buffer(tocXML, 'utf-8');
    let compressedTOC = deflateSync(tocXMLBuffer);

    let header = [
      XAR_MAGIC,
      XAR_HEADER_SIZE,
      1 /* version */,
      [0, compressedTOC.length],
      [0, tocXMLBuffer.length],
      XAR_CHECKSUM_SHA1
    ]
    let headerBuffer = new Buffer(XAR_HEADER_SIZE);
    this.ctypeParser.writeData([{ header: { type: 'xar_header', value: header } }], headerBuffer, 0);

    writer.write(headerBuffer);
    writer.write(compressedTOC);

    let heapWriter = new TrackingWriter(writer);

    // write TOC checksum
    let hash = createHash('sha1');
    hash.update(compressedTOC);
    let tocHash = hash.digest();
    assert(tocHash.length === digestSize(DigestAlgorithm.SHA1));
    heapWriter.write(tocHash);

    // write signature
    if (this.signatureResources) {
      let signer = createSign('SHA1');
      signer.update(compressedTOC);
      let signature: Buffer = <any>signer.sign(this.signatureResources.privateKey,
        undefined /* return a Buffer */);
      assert(signature.length === RSA_SIGNATURE_SIZE);
      heapWriter.write(signature);
    }

    // write compressed file content
    for (let file of fileList) {
      // verify that file data is being written to expected
      // location within the heap
      assert(heapWriter.bytesWritten === file.data.offset);
      assert(file.data.data.length === file.data.length);
      heapWriter.write(file.data.data);
    }
  }

  private readHeader(): XarHeader {
    let buf = this.reader.read(0, XAR_HEADER_SIZE);
    if (buf.length < XAR_HEADER_SIZE) {
      throw new Error('Not a valid xar archive. Input length is less than xar archive header size');
    }

    let {header } = this.ctypeParser.readData([{ header: { type: 'xar_header' } }], buf, 0);

    if (header.magic !== XAR_MAGIC) {
      throw new Error('Not a valid xar archive. Mime magic does not match "xar!"');
    }
    if (header.size < XAR_HEADER_SIZE) {
      throw new Error(`Not a valid xar archive. Header size is smaller than ${XAR_HEADER_SIZE} bytes`);
    }

    return {
      size: header.size,
      version: header.version,
      tocLengthCompressed: ctype.toAbs64(header.toc_length_compressed),
      tocLengthUncompressed: ctype.toAbs64(header.toc_length_uncompressed),
      checksumAlgorithm: header.cksum_alg
    };
  }

  private generateTOC() {
    let creationTime = new Date();
    let tocStruct: any = {
      xar: {
        toc: {
          'creation-time': creationTime.toISOString()
        }
      }
    };

    let tocRoot = tocStruct.xar.toc;
    let heapSize = 0;

    // checksum
    let checksumSize = digestSize(this.checksumAlgo);
    tocRoot.checksum = {
      $: {
        style: 'sha1'
      },
      size: checksumSize,
      offset: heapSize
    };
    heapSize += checksumSize;

    // signature
    if (this.signatureResources) {
      // 'signature-creation-time' is '%1.f' formatted seconds since
      // 2001-01-01T00:00:00Z
      let signatureCreationEpoch = new Date('2001-01-01T00:00:00Z');
      let signatureTimestamp = (creationTime.getTime() - signatureCreationEpoch.getTime()) / 1000.0

      let certEntries: string[] = [
        extractCertSection(this.signatureResources.cert),
        ...this.signatureResources.additionalCerts.map(extractCertSection)
      ];
      let signatureSize = RSA_SIGNATURE_SIZE;
      tocRoot['signature-creation-time'] = signatureTimestamp;
      tocRoot.signature = {
        $: {
          style: 'RSA'
        },
        offset: heapSize,
        size: signatureSize,
        'KeyInfo': {
          $: {
            xmlns: 'http://www.w3.org/2000/09/xmldsig'
          },
          'X509Data': {
            X509Certificate: certEntries
          }
        }
      };
      heapSize += signatureSize;
    }

    // file forest
    tocRoot.file = this.files.map(xarFileTOCEntry);

    return buildXML(tocStruct);
  }
}
