/** Node.js DNS adapter using node:dns/promises. Import only in Node runtimes. */
export declare function nodeResolve(hostname: string): Promise<string[]>;
export default nodeResolve;
