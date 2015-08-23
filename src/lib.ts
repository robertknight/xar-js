/// <reference path="../typings/tsd.d.ts" />

import * as xml2js from 'xml2js';
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import {createHash} from 'crypto';
import {gzipSync} from 'zlib';

/** A reference to a section of data within the 'heap' section
 * of a xar archive.
 */
export interface HeapRef {
  offset: number;
  size: number;
}

export enum FileType {
  File,
  Directory
}

enum Encoding {
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
  length: number;

  // Attributes which are set once the data has been
  // read and compressed
  encoding?: Encoding;
  heapRef?: HeapRef;
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
  console.log('generating XML from', JSON.stringify(obj, null, 2));
  let builder = new xml2js.Builder();
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
    if (!compressedFile.data.heapRef) {
      throw new Error(`Heap data missing for ${file.name}`);
    }
    if (!compressedFile.data.archivedChecksum) {
      throw new Error(`Archived checksum missing for ${file.name}`);
    }
    if (!compressedFile.data.extractedChecksum) {
      throw new Error(`Extracted checksum missing for ${file.name}`);
    }

    entry.data = {
      offset: compressedFile.data.heapRef.offset,
      size: compressedFile.data.heapRef.size,
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
      if (!file.data.heapRef) {
        // compress file data and set heap offset and length
        let reader = fileDataProvider(paths[index]);
        let sourceData = reader.read(0, file.data.length);
        assert(sourceData.length === file.data.length);
        file.data.data = gzipSync(sourceData);
        file.data.heapRef = {
          offset: heapSize,
          size: file.data.data.length
        };
        file.data.archivedChecksum = shasum(file.data.data);
        file.data.extractedChecksum = shasum(sourceData);
        heapSize += file.data.heapRef.size;
      }
    });

    let tocXML = this.generateTOC();
    let tocXMLBuffer = new Buffer(tocXML, 'utf-8');
    let compressedTOC = gzipSync(tocXMLBuffer);

    // write header
    // write TOC
    writer.write(compressedTOC);

    // write TOC checksum
    let hash = createHash('sha1');
    hash.update(compressedTOC);
    let tocHash = hash.digest();
    writer.write(tocHash);
    
    // TODO - Write signature (if any)

    // write file content
    for (let file of fileList) {
      writer.write(file.data.data);
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
