/// <reference path="../typings/tsd.d.ts" />

import * as xml2js from 'xml2js';
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import {createHash} from 'crypto';
import {deflateSync} from 'zlib';

var ctype: any = require('ctype');

export enum FileType {
  File,
  Directory
}

enum Encoding {
  // the xar file format supports several encodings, but
  // only 'gzip' is supported.

  // Note that despite being called 'gzip', the compressed
  // file data is not actually in gzip format but is actually just
  // compressed with deflate.
  // In other words, the compressed data does not have a gzip header.
  Gzip
}

export interface XarFile {
  id?: number;
  name: string;
  type: FileType;
}

export interface XarFileData {
  archivedChecksum?: string;
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

  data?: Buffer;
}

export interface XarCompressedFile extends XarFile {
  data: XarFileData;
}

export interface XarDirectory extends XarFile {
  children: XarFile[];
}

export interface Reader {
  read(offset: number, length: number): Buffer;
}

export interface Writer {
  write(data: Buffer): void;
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
  let xml: string;
  xml2js.parseString(content, {async: false}, (err, result) => {
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
  visit(path.join(dirPath, file.name), file);
  if (file.type === FileType.Directory) {
    (<XarDirectory>file).children.forEach(child => {
      walkFileTree(child, visit, path.join(dirPath, file.name));
    });
  }
}

export class XarArchive {
  private checksumAlgo: DigestAlgorithm;
  private files: XarFile[];

  constructor() {
    this.files = [];
    this.checksumAlgo = DigestAlgorithm.SHA1;
  }

  /** Add the metadata for a new file or directory tree to
   * the archive.
   *
   * The file's data is not actually read until generate() is called.
   */
  addFile(file: XarFile) {
    assert(file);
    this.files.push(file);
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
      walkFileTree(file, (_, file) => {
        maxID = file.id ? Math.max(file.id, maxID) : maxID;
      });
    });

    // if there is a signature, increment the heap size
    // by the signature size

    // create list of files to compress
    let fileList: XarCompressedFile[] = [];
    let paths: string[] = [];
    this.files.forEach(file => {
      walkFileTree(file, (path, file) => {
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

    // write header
    let ctypeParser = new ctype.Parser({endian: 'big'});
    ctypeParser.typedef('xar_header', [
      { magic: {type: 'uint32_t'} },
      { size:  {type: 'uint16_t'} },
      { version: {type: 'uint16_t'}},
      { toc_length_compressed: {type: 'uint64_t'} },
      { toc_length_uncompressed: {type: 'uint64_t'} },
      { cksum_alg: {type: 'uint32_t'}}
    ]);

    const XAR_HEADER_SIZE = 28;

    // "xar!"
    const XAR_MAGIC = 0x78617221;

    // checksum algorithms
    const XAR_CHECKSUM_SHA1 = 1;

    let header = [
      XAR_MAGIC,
      XAR_HEADER_SIZE,
      1 /* version */,
      [0, compressedTOC.length],
      [0, tocXMLBuffer.length],
      XAR_CHECKSUM_SHA1
    ]
    let headerBuffer = new Buffer(XAR_HEADER_SIZE);
    ctypeParser.writeData([{header: {type: 'xar_header', value: header}}], headerBuffer, 0);

    writer.write(headerBuffer);
    writer.write(compressedTOC);

    let heapWriter = new TrackingWriter(writer);

    // write TOC checksum
    let hash = createHash('sha1');
    hash.update(compressedTOC);
    let tocHash = hash.digest();
    heapWriter.write(tocHash);

    // TODO - Write signature (if any)

    // write file content
    for (let file of fileList) {
      // verify that file data is being written to expected
      // location within the heap
      assert(heapWriter.bytesWritten === file.data.offset);
      assert(file.data.data.length === file.data.length);
      heapWriter.write(file.data.data);
    }
  }

  private generateTOC() {
    let tocStruct: any = {
      xar: {
        toc: {}
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

    // TODO - Signature

    // file forest
    tocRoot.file = this.files.map(xarFileTOCEntry);

    return buildXML(tocStruct);
  }
}
