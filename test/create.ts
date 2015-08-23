/// <reference path="../typings/tsd.d.ts" />

import * as fs from 'fs';

import {XarArchive} from '../src/lib';
import {walk, FileReader, FileWriter} from '../src/util';

describe('create archives', () => {
  it('should create a xar archive', () => {
    const extensionDir = walk('./test/testextension.safariextension');

    const archive = new XarArchive();
    const writer = new FileWriter('test.safariextz');
    archive.addFile(extensionDir);
    archive.generate(writer, path => new FileReader('./test/' + path));
  });
});
