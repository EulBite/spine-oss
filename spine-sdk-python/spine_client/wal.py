# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Write-Ahead Log (WAL) for local event buffering.

Purpose:
- Buffer events when Spine server is unreachable
- Maintain local hash chain for integrity
- Provide resilience and ordering guarantees
- NOT a replacement for Spine (limited retention, no sealing)

Design:
- Append-only segments (immutable after write)
- Separate receipt log (also append-only)
- Configurable retention (time/size based)
- Per-stream hash chains

Important:
- WAL is a BUFFER, not a permanent audit log
- Events should be synced to Spine for audit-grade proof
- Local verification = "client integrity claim"
- Server receipt = "authoritative proof"
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, AsyncIterator, Callable, Any, Dict, Set
import aiofiles

from .types import LocalRecord, Receipt, generate_event_id, generate_stream_id
from .crypto import (
    canonical_json,
    hash_payload,
    compute_entry_hash,
    timestamp_to_nanos,
    SigningKey,
    HashAlgorithm,
)

logger = logging.getLogger(__name__)

# Genesis hash for first record in a stream
GENESIS_HASH = "0" * 64


@dataclass
class WALConfig:
    """WAL configuration."""
    data_dir: str = "./spine_wal"
    # Segment settings
    max_segment_size: int = 10 * 1024 * 1024  # 10MB per segment
    max_segments: int = 100                    # Max segment files
    # Retention (buffer, not permanent storage)
    retention_hours: int = 72                  # 3 days default
    # Compaction
    compact_on_startup: bool = True


class WAL:
    """
    Write-Ahead Log for local event buffering.

    NOT a replacement for Spine - this is a resilience buffer with limited retention.

    Usage:
        wal = WAL(signing_key, config)
        await wal.initialize()

        # Append event
        record = await wal.append(event_payload)

        # Sync to Spine, then attach receipt
        await wal.attach_receipt(record.event_id, receipt)

        # Verify local chain
        result = await wal.verify_local()

    Args:
        signing_key: Ed25519 key for signing events
        config: WAL configuration
        namespace: Optional namespace for stream isolation
    """

    def __init__(
        self,
        signing_key: SigningKey,
        config: Optional[WALConfig] = None,
        namespace: Optional[str] = None,
    ):
        self.signing_key = signing_key
        self.config = config or WALConfig()
        self.namespace = namespace

        self.data_dir = Path(self.config.data_dir)
        self.stream_id = generate_stream_id(signing_key.key_id, namespace)

        # Serialize all writes to guarantee:
        # 1. Monotonic sequence numbers (no duplicates under concurrent appends)
        # 2. Consistent prev_hash linkage (each entry sees the true previous)
        # 3. Atomic state updates (seq + prev_hash always in sync)
        # Trade-off: Single-writer bottleneck, but audit correctness > throughput
        self._lock = asyncio.Lock()
        self._initialized = False

        # Chain state invariant: _prev_hash == entry_hash(record at _seq)
        # Breaking this invariant = broken chain = verification failure
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._current_segment: Optional[Path] = None

    @property
    def _receipt_file(self) -> Path:
        """Path to the receipt log file."""
        return self.data_dir / "receipts.jsonl"

    @property
    def _state_file(self) -> Path:
        """Path to the chain state file."""
        return self.data_dir / "chain_state.json"

    async def initialize(self) -> None:
        """Initialize WAL, creating directory and recovering state."""
        if self._initialized:
            return

        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Recover chain state
        await self._recover_state()

        # Optional compaction on startup
        if self.config.compact_on_startup:
            await self._apply_retention()

        self._initialized = True
        logger.info(
            f"WAL initialized: stream={self.stream_id}, seq={self._seq}, "
            f"data_dir={self.data_dir}"
        )

    async def _recover_state(self) -> None:
        """Recover chain state from existing segments."""
        # Try to load saved state
        if self._state_file.exists():
            try:
                async with aiofiles.open(self._state_file, "r") as f:
                    state = json.loads(await f.read())
                    if state.get("stream_id") == self.stream_id:
                        self._seq = state.get("seq", 0)
                        self._prev_hash = state.get("prev_hash", GENESIS_HASH)
                        logger.debug(f"Recovered state: seq={self._seq}")
                        return
            except Exception as e:
                logger.warning(f"Failed to load state file: {e}")

        # Fallback: scan segments to recover max seq and last hash
        await self._rebuild_state_from_segments()

    async def _rebuild_state_from_segments(self) -> None:
        """Rebuild chain state by scanning all segments."""
        max_seq = 0
        last_entry_hash = GENESIS_HASH

        segments = sorted(self.data_dir.glob("segment_*.jsonl"))
        for segment in segments:
            try:
                async with aiofiles.open(segment, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                record = LocalRecord.from_dict(json.loads(line))
                                if record.stream_id == self.stream_id:
                                    if record.seq > max_seq:
                                        max_seq = record.seq
                                        # Recompute entry hash to get prev_hash for next entry
                                        ts_ns = timestamp_to_nanos(record.ts_client)
                                        last_entry_hash, _ = compute_entry_hash(
                                            seq=record.seq,
                                            timestamp_ns=ts_ns,
                                            prev_hash=record.prev_hash,
                                            payload_hash=record.payload_hash,
                                        )
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception as e:
                logger.warning(f"Error reading segment {segment}: {e}")

        self._seq = max_seq
        self._prev_hash = last_entry_hash
        logger.debug(f"Rebuilt state from segments: seq={self._seq}")

    async def _save_state(self) -> None:
        """Persist chain state to disk."""
        state = {
            "stream_id": self.stream_id,
            "seq": self._seq,
            "prev_hash": self._prev_hash,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            async with aiofiles.open(self._state_file, "w") as f:
                await f.write(json.dumps(state))
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def _get_current_segment(self) -> Path:
        """Get or create current segment file."""
        if self._current_segment and self._current_segment.exists():
            # Check size
            if self._current_segment.stat().st_size < self.config.max_segment_size:
                return self._current_segment

        # Create new segment
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._current_segment = self.data_dir / f"segment_{timestamp}.jsonl"
        return self._current_segment

    async def append(self, payload: Dict[str, Any]) -> LocalRecord:
        """
        Append an event to the WAL.

        Creates a LocalRecord with:
        - Unique event_id
        - Incrementing sequence number
        - Hash chain (prev_hash -> entry_hash for chain integrity)
        - Client signature over entry_hash (not just payload)

        Args:
            payload: Event payload dict

        Returns:
            LocalRecord with all crypto metadata
        """
        await self.initialize()

        async with self._lock:
            event_id = generate_event_id()
            self._seq += 1
            seq = self._seq
            ts_client = datetime.now(timezone.utc).isoformat()
            ts_ns = timestamp_to_nanos(ts_client)
            payload_hash, hash_alg = hash_payload(payload)

            # Entry hash binds (seq, timestamp, prev_hash, payload_hash) into one commitment.
            # This is what we sign and what becomes prev_hash for the next record.
            # Why sign entry_hash instead of payload?
            # - Payload-only signatures allow replay attacks (same payload, different position)
            # - Entry hash proves: "this exact payload, at this sequence, at this time, after that previous record"
            # MUST use BLAKE3 to match spine-cli verification (cross-language compatibility)
            entry_hash, _ = compute_entry_hash(
                seq=seq,
                timestamp_ns=ts_ns,
                prev_hash=self._prev_hash,
                payload_hash=payload_hash,
                algorithm=HashAlgorithm.BLAKE3,  # Always BLAKE3 for compatibility with CLI
            )

            signature = self.signing_key.sign_hex(entry_hash.encode('utf-8'))

            # Store both key_id (human-friendly, for key rotation tracking) and
            # public_key (64 hex chars, for CLI signature verification without key lookup)
            record = LocalRecord(
                event_id=event_id,
                stream_id=self.stream_id,
                seq=seq,
                prev_hash=self._prev_hash,
                ts_client=ts_client,
                payload=payload,
                payload_hash=payload_hash,
                hash_alg=hash_alg,
                sig_client=signature,
                key_id=self.signing_key.key_id,
                public_key=self.signing_key.public_key().to_hex(),
                receipt=None,
            )

            # Write to segment
            segment = self._get_current_segment()
            async with aiofiles.open(segment, "a") as f:
                await f.write(json.dumps(record.to_dict()) + "\n")
                await f.flush()

            # Update chain state: next entry's prev_hash = this entry's entry_hash
            self._prev_hash = entry_hash
            await self._save_state()

            logger.debug(f"WAL append: event_id={event_id}, seq={seq}")
            return record

    async def attach_receipt(self, event_id: str, receipt: Receipt) -> bool:
        """
        Attach a server receipt to an event.

        Called after successful sync to Spine.

        Args:
            event_id: ID of the event
            receipt: Server receipt

        Returns:
            True if receipt was attached successfully
        """
        await self.initialize()

        async with self._lock:
            receipt_entry = {
                "event_id": event_id,
                "receipt": receipt.to_dict(),
                "attached_at": datetime.now(timezone.utc).isoformat(),
            }

            try:
                async with aiofiles.open(self._receipt_file, "a") as f:
                    await f.write(json.dumps(receipt_entry) + "\n")
                    await f.flush()
                logger.debug(f"Receipt attached: event_id={event_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to attach receipt for {event_id}: {e}")
                return False

    async def get_record(self, event_id: str) -> Optional[LocalRecord]:
        """
        Get a record by event ID.

        Merges receipt from receipt log if present.

        Args:
            event_id: Event ID to find

        Returns:
            LocalRecord if found, None otherwise
        """
        await self.initialize()

        receipts = await self._load_receipts()
        segments = sorted(self.data_dir.glob("segment_*.jsonl"))
        for segment in segments:
            try:
                async with aiofiles.open(segment, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                record = LocalRecord.from_dict(json.loads(line))
                                if record.event_id == event_id:
                                    if event_id in receipts:
                                        record.receipt = receipts[event_id]
                                    return record
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception:
                continue

        return None

    async def _load_receipts(self, event_ids: Optional[Set[str]] = None) -> Dict[str, Receipt]:
        """
        Load receipts from the receipt log.

        Memory-efficient: if event_ids is provided, only loads receipts for those IDs.
        Otherwise loads all (use with caution on large files).

        Args:
            event_ids: Optional set of event IDs to load receipts for.
                       If None, loads all receipts (memory-intensive for large logs).

        Returns:
            Dict mapping event_id -> Receipt
        """
        receipts = {}
        if not self._receipt_file.exists():
            return receipts

        try:
            async with aiofiles.open(self._receipt_file, "r") as f:
                async for line in f:
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            event_id = entry["event_id"]
                            # Skip if not in requested set (when filtering)
                            if event_ids is not None and event_id not in event_ids:
                                continue
                            receipt = Receipt.from_dict(entry["receipt"])
                            receipts[event_id] = receipt
                        except (json.JSONDecodeError, KeyError):
                            continue
        except Exception as e:
            logger.warning(f"Error loading receipts: {e}")

        return receipts

    async def _load_synced_event_ids(self) -> Set[str]:
        """
        Load only event IDs that have receipts (memory-efficient).

        Returns:
            Set of event IDs with receipts
        """
        synced_ids: Set[str] = set()
        if not self._receipt_file.exists():
            return synced_ids

        try:
            async with aiofiles.open(self._receipt_file, "r") as f:
                async for line in f:
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            synced_ids.add(entry["event_id"])
                        except (json.JSONDecodeError, KeyError):
                            continue
        except Exception as e:
            logger.warning(f"Error loading synced event IDs: {e}")

        return synced_ids

    async def unsynced_records(self, limit: int) -> List[LocalRecord]:
        """
        Get a batch of records without server receipts.

        IMPORTANT: This returns at most `limit` records. Use `unsynced_count()`
        to check if there are more records pending, or call repeatedly until
        the returned list is smaller than `limit`.

        Args:
            limit: Maximum records to return (required, no default to avoid silent truncation)

        Returns:
            List of LocalRecord without receipts (up to `limit`)

        Example:
            # Process all unsynced in batches
            while True:
                batch = await wal.unsynced_records(limit=100)
                if not batch:
                    break
                for record in batch:
                    await sync_to_server(record)
        """
        await self.initialize()

        synced_ids = await self._load_synced_event_ids()
        unsynced = []
        segments = sorted(self.data_dir.glob("segment_*.jsonl"))

        for segment in segments:
            if len(unsynced) >= limit:
                break

            try:
                async with aiofiles.open(segment, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                record = LocalRecord.from_dict(json.loads(line))
                                if record.stream_id == self.stream_id:
                                    if record.event_id not in synced_ids:
                                        unsynced.append(record)
                                        if len(unsynced) >= limit:
                                            break
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception:
                continue

        return unsynced

    async def unsynced_count(self) -> int:
        """
        Count records without server receipts.

        This scans all segments but only counts, doesn't load full records.
        Use this to check if there's a backlog before/after processing.

        Returns:
            Number of unsynced records
        """
        await self.initialize()

        synced_ids = await self._load_synced_event_ids()
        count = 0

        segments = sorted(self.data_dir.glob("segment_*.jsonl"))
        for segment in segments:
            try:
                async with aiofiles.open(segment, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if data.get("stream_id") == self.stream_id:
                                    if data.get("event_id") not in synced_ids:
                                        count += 1
                            except json.JSONDecodeError:
                                continue
            except Exception:
                continue

        return count

    async def iter_records(
        self,
        stream_id: Optional[str] = None,
    ) -> AsyncIterator[LocalRecord]:
        """
        Iterate over all records in the WAL.

        Args:
            stream_id: Filter by stream ID (None = this WAL's stream)

        Yields:
            LocalRecord objects
        """
        await self.initialize()

        target_stream = stream_id or self.stream_id
        receipts = await self._load_receipts()

        segments = sorted(self.data_dir.glob("segment_*.jsonl"))
        for segment in segments:
            try:
                async with aiofiles.open(segment, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                record = LocalRecord.from_dict(json.loads(line))
                                if record.stream_id == target_stream:
                                    if record.event_id in receipts:
                                        record.receipt = receipts[record.event_id]
                                    yield record
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception:
                continue

    async def _apply_retention(self) -> Dict[str, int]:
        """
        Apply retention policy - remove old segments.

        Returns:
            Stats about removed segments
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.config.retention_hours)
        segments = sorted(self.data_dir.glob("segment_*.jsonl"))

        removed = 0
        kept = 0

        for segment in segments[:-1] if len(segments) > 1 else []:
            try:
                # segment_20250115_120000.jsonl
                name = segment.stem
                ts_str = name.replace("segment_", "")
                segment_time = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                segment_time = segment_time.replace(tzinfo=timezone.utc)

                if segment_time < cutoff:
                    segment.unlink()
                    removed += 1
                    logger.info(f"Retention: removed {segment.name}")
                else:
                    kept += 1
            except (ValueError, OSError) as e:
                logger.warning(f"Retention error for {segment}: {e}")
                kept += 1

        return {"removed": removed, "kept": kept + 1}  # +1 for current/last

    async def get_stats(self) -> Dict[str, Any]:
        """Get WAL statistics."""
        await self.initialize()

        segments = list(self.data_dir.glob("segment_*.jsonl"))
        total_size = sum(s.stat().st_size for s in segments)

        receipts = await self._load_receipts()

        return {
            "stream_id": self.stream_id,
            "key_id": self.signing_key.key_id,
            "seq": self._seq,
            "segment_count": len(segments),
            "total_size_bytes": total_size,
            "receipts_count": len(receipts),
            "unsynced_count": await self.unsynced_count(),
            "data_dir": str(self.data_dir),
            "retention_hours": self.config.retention_hours,
        }
