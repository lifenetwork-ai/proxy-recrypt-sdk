import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  generateRandomSymmetricKeyFromGT,
} from "../crypto/index";
import { combineSecret, splitSecret } from "../shamir/index";
import { PreClient } from "../pre";
import {
  loadAliceKeyPair,
  loadRandomScalar,
} from "../utils/testUtils";

/**
 * Generates a random file of specified size
 * @param filename The name of the file to create
 * @param sizeInBytes The size of the file in bytes
 */
const generateRandomFile = async (
  filename: string,
  sizeInBytes: number
): Promise<void> => {
  console.log(
    `Generating random file: ${filename} (${sizeInBytes / (1024 * 1024)} MB)`
  );

  const chunkSize = 1024 * 1024; // Generate in 1MB chunks for memory efficiency
  const fd = fs.openSync(filename, "w");

  try {
    let remainingBytes = sizeInBytes;

    while (remainingBytes > 0) {
      const currentChunkSize = Math.min(chunkSize, remainingBytes);
      const randomData = crypto.randomBytes(currentChunkSize);
      fs.writeSync(fd, randomData);
      remainingBytes -= currentChunkSize;
    }

    // Log progress for large files
    if (
      sizeInBytes > 10 * 1024 * 1024 &&
      remainingBytes % (5 * 1024 * 1024) === 0
    ) {
      console.log(
        `Progress: ${Math.round((1 - remainingBytes / sizeInBytes) * 100)}%`
      );
    }
    console.log(`File generated successfully: ${filename}`);
  } finally {
    // Always close the file descriptor when done
    fs.closeSync(fd);
  }
};

/**
 * Runs a benchmark with timing information
 * @param name Name of the benchmark
 * @param fn Function to benchmark
 */
const runBenchmark = async <T>(
  name: string,
  fn: () => Promise<T>
): Promise<T> => {
  console.log(`Starting benchmark: ${name}`);
  const startTime = performance.now();

  try {
    const result = await fn();
    const endTime = performance.now();
    const duration = endTime - startTime;

    console.log(`Benchmark ${name} completed in ${duration.toFixed(2)}ms`);
    return result;
  } catch (error) {
    console.error(`Benchmark ${name} failed:`, error);
    throw error;
  }
};

/**
 * Main benchmark suite
 */
const runBenchmarks = async () => {
  // Create benchmark directory if it doesn't exist
  const benchmarkDir = path.join(process.cwd(), "benchmark_files");
  try {
    await fs.mkdirSync(benchmarkDir, { recursive: true });
  } catch (err) {
    // Directory already exists, continue
  }

  // Generate test files of different sizes
  const testFileSizes = [
    { name: "small.txt", size: 100 * 1024 }, // 100KB
    { name: "medium.txt", size: 1 * 1024 * 1024 }, // 1MB
    { name: "medium-large.txt", size: 10 * 1024 * 1024 }, // 16MB
    { name: "large.txt", size: 100 * 1024 * 1024 }, // 64MB
  ];

  for (const file of testFileSizes) {
    const filePath = path.join(benchmarkDir, file.name);
    await generateRandomFile(filePath, file.size);
  }

  // Benchmark results storage
  const results: Record<
    string,
    {
      fileSize: number;
      encryptedSize: number;
      encryptionTime: number;
      decryptionTime?: number;
      overhead?: number;
    }
  > = {};

  // Run benchmarks for each file size
  for (const file of testFileSizes) {
    const filePath = path.join(benchmarkDir, file.name);
    const fileContent = await fs.readFileSync(filePath, "utf-8");
    const fileSize = Buffer.from(fileContent).length;

    console.log(
      `\n=== Benchmarking with ${file.name} (${fileSize / 1024} KB) ===`
    );

    // Step 1: Generate secret and shares
    const secret = Buffer.from((await generateRandomSymmetricKeyFromGT()).key);

    const threshold = 2;
    const totalShares = 3;

    // Step 2: Split the secret
    const sharesArray = await splitSecret(secret, threshold, totalShares);

    const keypair = await loadAliceKeyPair();
    const scalar = await loadRandomScalar();
    // Step 3: Combine subset of shares to reconstruct secret
    await runBenchmark(
      "Secret Reconstruction",
      async () => {
        return combineSecret([sharesArray[0], sharesArray[1]]);
      }
    );

    // Step 4: Encryption benchmark
    const client = new PreClient();

    const encryptionTime = performance.now();
    const secondLevelResponse = await runBenchmark(
      "Second Level Encryption",
      async () => {
        return client.secondLevelEncryption(
          keypair.secretKey,
          Buffer.from(fileContent),
          scalar
        );
      }
    );
    const encryptionEndTime = performance.now();

    // Calculate encrypted data size
    const encryptedSize = secondLevelResponse.encryptedMessage.length;
    console.log(
      `Original size: ${fileSize} bytes, Encrypted size: ${encryptedSize} bytes`
    );

    // Calculate overhead percentage
    const overhead = ((encryptedSize - fileSize) / fileSize) * 100;

    // Store results
    results[file.name] = {
      fileSize,
      encryptedSize,
      encryptionTime: encryptionEndTime - encryptionTime,
      overhead,
    };

    // Optional: Add decryption benchmark if your PreClient has a decryption method
    /*
    const decryptionTime = performance.now();
    await runBenchmark('Decryption', async () => {
      return client.decrypt(
        secondLevelResponse,
        { ... necessary params for decryption ... }
      );
    });
    const decryptionEndTime = performance.now();
    results[file.name].decryptionTime = decryptionEndTime - decryptionTime;
    */
  }

  // Print overall results
  console.log("\n=== BENCHMARK RESULTS ===");
  console.log(
    "File Size (KB) | Encrypted Size (KB) | Overhead (%) | Encryption Time (ms) | Throughput (KB/s)"
  );
  console.log(
    "-------------- | ------------------- | ------------ | -------------------- | -----------------"
  );

  Object.entries(results).forEach(([, result]) => {
    const fileSizeKB = result.fileSize / 1024;
    const encryptedSizeKB = result.encryptedSize / 1024;
    const throughput = fileSizeKB / (result.encryptionTime / 1000);
    console.log(
      `${fileSizeKB.toFixed(2).padEnd(14)} | ${encryptedSizeKB
        .toFixed(2)
        .padEnd(19)} | ${result.overhead
        ?.toFixed(2)
        .padEnd(12)} | ${result.encryptionTime
        .toFixed(2)
        .padEnd(20)} | ${throughput.toFixed(2)}`
    );
  });
};

// Run the benchmark suite
runBenchmarks().catch((error) => {
  console.error("Benchmark failed:", error);
});
