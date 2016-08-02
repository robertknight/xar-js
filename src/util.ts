import * as fs from 'fs';
import * as path from 'path';

import {
FileType,
  XarFile,
  XarDirectory,
  XarCompressedFile
} from './lib';

/** Process a file or directory tree and create a XarFile representing
 * its contents.
 */
export function walk(filePath: string, isTopLevel?: boolean): XarFile {
  let fileInfo = fs.statSync(filePath);
  let children: XarFile[];
  if (fileInfo.isDirectory()) {
    return <XarDirectory>{
      name: isTopLevel ? filePath : path.basename(filePath),
      type: FileType.Directory,
      children: fs.readdirSync(filePath).map(basename => walk(path.join(filePath, basename)))
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
