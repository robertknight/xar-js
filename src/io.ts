import * as fs from 'fs';

/** Interface used by XarArchive to read
 * data from a file or other data source.
 */
export interface Reader {
  read(offset: number, length: number): Buffer;
}

/** Interface used by XarArchive to write data
 * to a file or other data sink.
 */
export interface Writer {
  write(data: Buffer): void;
}

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
