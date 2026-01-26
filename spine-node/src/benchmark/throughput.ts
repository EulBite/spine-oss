// SPDX-License-Identifier: Apache-2.0

/**
 * Spine Node SDK Benchmark
 *
 * Measures:
 * - Append throughput (events/sec)
 * - Verify throughput (events/sec)
 * - Attestation generation time
 *
 * Run: npx ts-node benchmark/throughput.ts
 * Or:  node dist/benchmark/throughput.js
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SigningKey, WAL, verify, exportAttestation } from '../index.js';

interface BenchmarkResult {
  name: string;
  count: number;
  totalMs: number;
  opsPerSec: number;
  avgMs: number;
}

function formatNumber(n: number): string {
  return n.toLocaleString('en-US', { maximumFractionDigits: 2 });
}

function printResult(result: BenchmarkResult): void {
  console.log(`\n${result.name}`);
  console.log(`  Count:      ${formatNumber(result.count)} operations`);
  console.log(`  Total:      ${formatNumber(result.totalMs)} ms`);
  console.log(`  Throughput: ${formatNumber(result.opsPerSec)} ops/sec`);
  console.log(`  Avg:        ${formatNumber(result.avgMs)} ms/op`);
}

async function benchmarkAppend(wal: WAL, count: number): Promise<BenchmarkResult> {
  const start = performance.now();

  for (let i = 0; i < count; i++) {
    await wal.append({
      event_type: 'benchmark.event',
      seq: i,
      timestamp: new Date().toISOString(),
      data: { value: Math.floor(Math.random() * 1000000) },
    });
  }

  const totalMs = performance.now() - start;

  return {
    name: 'APPEND (write + sign + hash)',
    count,
    totalMs,
    opsPerSec: (count / totalMs) * 1000,
    avgMs: totalMs / count,
  };
}

async function benchmarkVerify(wal: WAL, expectedCount: number): Promise<BenchmarkResult> {
  const start = performance.now();
  const result = await verify(wal);
  const totalMs = performance.now() - start;

  if (result.count !== expectedCount) {
    throw new Error(`Verify count mismatch: ${result.count} vs ${expectedCount}`);
  }

  return {
    name: 'VERIFY (read + verify signatures + check hashes)',
    count: expectedCount,
    totalMs,
    opsPerSec: (expectedCount / totalMs) * 1000,
    avgMs: totalMs / expectedCount,
  };
}

async function benchmarkAttestation(
  wal: WAL,
  signingKey: SigningKey,
  iterations: number
): Promise<BenchmarkResult> {
  const start = performance.now();

  for (let i = 0; i < iterations; i++) {
    await exportAttestation(wal, signingKey);
  }

  const totalMs = performance.now() - start;

  return {
    name: 'ATTESTATION (verify + sign)',
    count: iterations,
    totalMs,
    opsPerSec: (iterations / totalMs) * 1000,
    avgMs: totalMs / iterations,
  };
}

async function main(): Promise<void> {
  const EVENT_COUNT = 1_000;
  const ATTESTATION_ITERATIONS = 10;

  console.log('='.repeat(60));
  console.log('SPINE NODE SDK BENCHMARK');
  console.log('='.repeat(60));
  console.log(`\nConfig:`);
  console.log(`  Events to append:       ${formatNumber(EVENT_COUNT)}`);
  console.log(`  Attestation iterations: ${formatNumber(ATTESTATION_ITERATIONS)}`);
  console.log(`  Node.js:                ${process.version}`);
  console.log(`  Platform:               ${os.platform()} ${os.arch()}`);
  console.log(`  CPUs:                   ${os.cpus().length}x ${os.cpus()[0].model}`);

  // Setup
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spine-bench-'));
  console.log(`\nWAL directory: ${testDir}`);

  try {
    const signingKey = await SigningKey.generate('bench-key');
    const wal = new WAL(signingKey, { dataDir: testDir });

    // Warmup
    console.log('\nWarmup (100 events)...');
    for (let i = 0; i < 100; i++) {
      await wal.append({ warmup: true, i });
    }

    // New WAL for actual benchmark
    const benchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spine-bench2-'));
    const benchWal = new WAL(signingKey, { dataDir: benchDir });

    console.log('\nRunning benchmarks...');

    // Benchmark append
    const appendResult = await benchmarkAppend(benchWal, EVENT_COUNT);
    printResult(appendResult);

    // Benchmark verify
    const verifyResult = await benchmarkVerify(benchWal, EVENT_COUNT);
    printResult(verifyResult);

    // Benchmark attestation
    const attestResult = await benchmarkAttestation(benchWal, signingKey, ATTESTATION_ITERATIONS);
    printResult(attestResult);

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('SUMMARY');
    console.log('='.repeat(60));
    console.log(`\n  Append:      ${formatNumber(appendResult.opsPerSec)} events/sec`);
    console.log(`  Verify:      ${formatNumber(verifyResult.opsPerSec)} events/sec`);
    console.log(`  Attestation: ${formatNumber(attestResult.opsPerSec)} attestations/sec`);

    // Memory
    const mem = process.memoryUsage();
    console.log(`\nMemory:`);
    console.log(`  Heap used:   ${formatNumber(mem.heapUsed / 1024 / 1024)} MB`);
    console.log(`  Heap total:  ${formatNumber(mem.heapTotal / 1024 / 1024)} MB`);
    console.log(`  RSS:         ${formatNumber(mem.rss / 1024 / 1024)} MB`);

    // Cleanup
    fs.rmSync(benchDir, { recursive: true, force: true });

  } finally {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
}

main().catch(console.error);
