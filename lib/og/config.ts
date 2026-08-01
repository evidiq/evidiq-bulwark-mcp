export interface OgConfig {
  privateKey: string;
  rpcUrl: string;
  indexerUrl: string;
}

export function getOgConfig(): OgConfig | null {
  const privateKey = process.env.OG_PRIVATE_KEY;
  if (!privateKey || privateKey.startsWith("0x00000000")) {
    return null;
  }
  return {
    privateKey,
    rpcUrl: process.env.OG_STORAGE_RPC || "https://evmrpc.0g.ai",
    indexerUrl: process.env.OG_STORAGE_INDEXER || "https://indexer-storage-turbo.0g.ai",
  };
}
