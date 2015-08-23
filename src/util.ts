import * as fs from 'fs';
import * as path from 'path';

import {FileType,
        XarFile,
        XarDirectory,
        XarCompressedFile,
        Reader, Writer} from './lib';

export class FileWriter implements Writer {
  private fd: number;

  constructor(path: string) {
    this.fd = fs.openSync(path, 'w');
  }

  write(data: Buffer) {
    fs.writeSync(this.fd, data, 0, data.length, null /* write from current pos */);
  }
}

export class FileReader implements Reader {
  private fd: number;

  constructor(path: string) {
    this.fd = fs.openSync(path, 'r');
  }

  read(offset: number, length: number): Buffer {
    let buf = new Buffer(length);
    fs.readSync(this.fd, buf, 0, length, offset);
    return buf;
  }
}

/** Process a file or directory tree and create a XarFile representing
 * its contents.
 */
 export function walk(filePath: string): XarFile {
   let fileInfo = fs.statSync(filePath);
   let children: XarFile[];
   if (fileInfo.isDirectory()) {
     return <XarDirectory>{
       name: path.basename(filePath),
       type: FileType.Directory,
       children: fs.readdirSync(filePath).map(basename => walk(path.join(filePath,basename)))
     };
   } else {
     return <XarCompressedFile>{
       name: path.basename(filePath),
       type: FileType.File,
       data: {
         size: fileInfo.size
       }
     }
   }
 }
