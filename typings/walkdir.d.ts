/// <reference path="node/node.d.ts" />

declare module "walkdir" {
  import * as fs from "fs";

  interface Walker {
    (path: string, callback: (path: string, stat: fs.Stats) => any): NodeJS.EventEmitter;
    sync(path: string, callback: (path: string, stat: fs.Stats) => any): string[];
  }

  var walker: Walker;
  export = walker;
}
