declare module "tar-stream" {
  import { Transform, Readable, Writable } from "stream"

  interface Header {
    name: string
    size: number
    mode: number
    mtime: Date
    type: string
    [key: string]: any
  }

  interface Pack extends Transform {
    entry(header: Header, data?: string | Buffer | Readable, callback?: (err?: Error) => void): boolean
    finalize(): void
  }

  interface Extract extends Transform {
    on(event: "entry", listener: (header: Header, stream: Readable, next: () => void) => void): Extract
    on(event: "finish", listener: () => void): Extract
    on(event: "error", listener: (err: Error) => void): Extract
  }

  function pack(): Pack
  function extract(): Extract

  export { pack, extract, Header, Pack, Extract }
}
