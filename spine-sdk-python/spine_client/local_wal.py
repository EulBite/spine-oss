# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
**DEPRECATED**: Use `wal.WAL` instead for cryptographically signed logs.

This module provides a simple offline buffer WITHOUT cryptographic signatures.
Events stored here are NOT verifiable with spine-cli.

Migration guide::

    # Old (deprecated):
    from spine_client import LocalWAL
    wal = LocalWAL(data_dir="./fallback")

    # New (recommended):
    from spine_client import WAL, WALConfig, SigningKey
    key = SigningKey.generate()
    wal = WAL(key, WALConfig(data_dir="./fallback"))

Why deprecated?
    - LocalWAL has no Ed25519 signatures (cannot prove who wrote the event)
    - LocalWAL has no BLAKE3 hash chain (cannot prove event ordering)
    - LocalWAL is NOT verifiable with spine-cli
    - For "standalone-first" consistency, all WAL storage should be signed

This module is kept for backward compatibility only. It may be removed in v1.0.
"""

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, AsyncIterator, Callable, Any, Dict
import logging
import aiofiles

logger = logging.getLogger(__name__)


@dataclass
class SyncState:
    """Sync state for a WAL entry, stored in separate sync log."""
    synced: bool = False
    sync_attempts: int = 0
    last_sync_error: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class WALEntry:
    """Single entry in the local WAL."""
    sequence: int
    timestamp: str
    event: dict
    # Sync state is now tracked separately but merged on read
    synced: bool = False
    sync_attempts: int = 0
    last_sync_error: Optional[str] = None

    def to_json(self) -> str:
        """Serialize for WAL storage (excludes sync state for immutability)."""
        return json.dumps({
            "seq": self.sequence,
            "ts": self.timestamp,
            "event": self.event,
        })

    def to_json_with_state(self) -> str:
        """Serialize with sync state (for full export/inspection)."""
        return json.dumps({
            "seq": self.sequence,
            "ts": self.timestamp,
            "event": self.event,
            "synced": self.synced,
            "sync_attempts": self.sync_attempts,
            "last_sync_error": self.last_sync_error,
        })

    @classmethod
    def from_json(cls, line: str) -> "WALEntry":
        data = json.loads(line)
        return cls(
            sequence=data["seq"],
            timestamp=data["ts"],
            event=data["event"],
            # Sync state may not be present in immutable WAL entries
            synced=data.get("synced", False),
            sync_attempts=data.get("sync_attempts", 0),
            last_sync_error=data.get("last_sync_error"),
        )


class LocalWAL:
    """
    **DEPRECATED**: Use `wal.WAL` instead for cryptographically signed logs.

    Local Write-Ahead Log for buffering events when Spine is unavailable.
    This class does NOT provide cryptographic signatures or hash chains.
    Events stored here cannot be verified with spine-cli.

    .. deprecated:: 0.2.0
        Use :class:`wal.WAL` with a :class:`crypto.SigningKey` instead.

    Args:
        data_dir: Directory for WAL files
        max_file_size: Maximum size per WAL file (bytes)
        max_files: Maximum number of WAL files to keep
        sync_callback: Optional callback for syncing to Spine
    """

    def __init__(
        self,
        data_dir: str = "/var/spine/fallback",
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        max_files: int = 100,
        sync_callback: Optional[Callable[[dict], Any]] = None,
    ):
        import warnings
        warnings.warn(
            "LocalWAL is deprecated and will be removed in v1.0. "
            "Use WAL with SigningKey for CLI-verifiable logs. "
            "See: https://github.com/eulbite/spine/blob/main/spine-sdk-python/README.md",
            DeprecationWarning,
            stacklevel=2,
        )
        self.data_dir = Path(data_dir)
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.sync_callback = sync_callback

        self._sequence = 0
        self._current_file: Optional[Path] = None
        self._lock = asyncio.Lock()
        self._sync_lock = asyncio.Lock()  # Single-flight sync protection
        self._initialized = False
        # In-memory cache of sync states (rebuilt from sync log on init)
        # Call compact_sync_state() periodically to reduce memory usage
        self._sync_states: Dict[int, SyncState] = {}

    @property
    def _sync_state_file(self) -> Path:
        """Path to the sync state log file."""
        return self.data_dir / "sync_state.jsonl"

    async def initialize(self) -> None:
        """Initialize the WAL, creating directory and recovering state."""
        if self._initialized:
            return

        self.data_dir.mkdir(parents=True, exist_ok=True)
        await self._load_sync_states()

        # Find existing WAL files and recover max sequence across ALL files
        # This fixes the bug where only the last file was checked
        wal_files = sorted(self.data_dir.glob("wal_*.jsonl"))
        max_seq = 0

        for wal_file in wal_files:
            try:
                async with aiofiles.open(wal_file, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                entry = WALEntry.from_json(line)
                                max_seq = max(max_seq, entry.sequence)
                            except (json.JSONDecodeError, KeyError) as e:
                                logger.warning(f"Corrupted entry in {wal_file}: {e}")
                                continue
            except Exception as e:
                logger.warning(f"Error reading WAL file {wal_file}: {e}")
                continue

        self._sequence = max_seq

        if wal_files:
            self._current_file = wal_files[-1]
        else:
            self._current_file = self._new_wal_file()

        self._initialized = True
        logger.info(f"LocalWAL initialized: {self.data_dir}, sequence={self._sequence}")

    async def _load_sync_states(self) -> None:
        """Load sync states from the sync state log file."""
        self._sync_states = {}

        if not self._sync_state_file.exists():
            return

        try:
            async with aiofiles.open(self._sync_state_file, "r") as f:
                async for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            seq = data["seq"]
                            state = SyncState(
                                synced=data.get("synced", False),
                                sync_attempts=data.get("sync_attempts", 0),
                                last_sync_error=data.get("last_sync_error"),
                                updated_at=data.get("ts"),
                            )
                            self._sync_states[seq] = state
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.warning(f"Corrupted sync state entry: {e}")
                            continue
        except Exception as e:
            logger.warning(f"Error loading sync states: {e}")

    def _new_wal_file(self) -> Path:
        """Create a new WAL file with timestamp."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self.data_dir / f"wal_{timestamp}.jsonl"

    async def _rotate_if_needed(self) -> None:
        """Rotate to new file if current file is too large."""
        if self._current_file and self._current_file.exists():
            size = self._current_file.stat().st_size
            if size >= self.max_file_size:
                self._current_file = self._new_wal_file()
                logger.info(f"WAL rotated to {self._current_file}")
                await self._cleanup_old_files()

    async def _cleanup_old_files(self) -> None:
        """Remove old WAL files beyond max_files limit."""
        wal_files = sorted(self.data_dir.glob("wal_*.jsonl"))
        # Keep files with unsynced entries
        files_to_check = wal_files[:-self.max_files] if len(wal_files) > self.max_files else []

        for wal_file in files_to_check:
            has_unsynced = False
            try:
                async with aiofiles.open(wal_file, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                entry = WALEntry.from_json(line)
                                # Check sync state from cache
                                if entry.sequence in self._sync_states:
                                    if not self._sync_states[entry.sequence].synced:
                                        has_unsynced = True
                                        break
                                else:
                                    # No sync state means not synced
                                    has_unsynced = True
                                    break
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception as e:
                logger.warning(f"Error checking WAL file {wal_file}: {e}")
                continue

            if not has_unsynced:
                try:
                    wal_file.unlink()
                    logger.info(f"Removed fully synced WAL file: {wal_file}")
                except Exception as e:
                    logger.warning(f"Failed to remove WAL file {wal_file}: {e}")

    async def append(self, event: dict) -> int:
        """
        Append an event to the local WAL.

        Args:
            event: Event dictionary to store

        Returns:
            Sequence number assigned to this event
        """
        await self.initialize()

        async with self._lock:
            await self._rotate_if_needed()

            self._sequence += 1
            entry = WALEntry(
                sequence=self._sequence,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event=event,
                synced=False,
            )

            async with aiofiles.open(self._current_file, "a") as f:
                await f.write(entry.to_json() + "\n")
                await f.flush()

            logger.debug(f"WAL append: seq={self._sequence}")
            return self._sequence

    async def unsynced_entries(self, limit: int) -> AsyncIterator[WALEntry]:
        """
        Iterate over a batch of unsynced entries across all WAL files.

        IMPORTANT: This yields at most `limit` entries. Call repeatedly until
        no more entries are returned to process the full backlog.

        Merges sync state from the sync log with WAL entries.

        Args:
            limit: Maximum entries to return (required, no default to avoid silent truncation).
                   Use limit=0 for unlimited (only for small WALs, logs a warning).

        Yields:
            WALEntry objects that haven't been synced yet (up to `limit`)

        Example:
            # Process all unsynced in batches
            while True:
                batch = [e async for e in wal.unsynced_entries(limit=100)]
                if not batch:
                    break
                for entry in batch:
                    await sync_to_server(entry)
        """
        if limit == 0:
            logger.warning(
                "unsynced_entries(limit=0) loads all entries into memory. "
                "Consider using a limit for large WALs."
            )
        # Collect entries while holding lock, then yield outside lock
        entries = await self._collect_unsynced_entries(limit=limit)
        for entry in entries:
            yield entry

    async def _collect_unsynced_entries(self, limit: int = 0) -> List["WALEntry"]:
        """
        Internal: Collect unsynced entries while holding the lock.

        Uses windowed approach: only collects up to `limit` entries to avoid
        loading entire WAL into memory for large backlogs.

        Args:
            limit: Maximum entries to collect (0 = unlimited)

        Returns:
            List of unsynced WALEntry objects (up to limit)
        """
        await self.initialize()

        entries: List[WALEntry] = []

        # Use lock to prevent concurrent modification during collection
        async with self._lock:
            wal_files = sorted(self.data_dir.glob("wal_*.jsonl"))
            for wal_file in wal_files:
                # Early exit if we've collected enough
                if limit > 0 and len(entries) >= limit:
                    break

                try:
                    async with aiofiles.open(wal_file, "r") as f:
                        async for line in f:
                            if line.strip():
                                try:
                                    entry = WALEntry.from_json(line)
                                    # Merge sync state from in-memory cache
                                    if entry.sequence in self._sync_states:
                                        state = self._sync_states[entry.sequence]
                                        entry.synced = state.synced
                                        entry.sync_attempts = state.sync_attempts
                                        entry.last_sync_error = state.last_sync_error
                                    if not entry.synced:
                                        entries.append(entry)
                                        # Early exit if we've collected enough
                                        if limit > 0 and len(entries) >= limit:
                                            break
                                except (json.JSONDecodeError, KeyError) as e:
                                    logger.warning(f"Corrupted entry in {wal_file}: {e}")
                                    continue
                except Exception as e:
                    logger.warning(f"Error reading WAL file {wal_file}: {e}")
                    continue

        return entries

    async def update_entry(
        self,
        sequence: int,
        synced: Optional[bool] = None,
        sync_attempts: Optional[int] = None,
        last_sync_error: Optional[str] = None,
    ) -> bool:
        """
        Update an entry's sync state in the append-only sync log.

        This maintains forensic integrity by NEVER modifying the original WAL files.
        Instead, sync state updates are appended to a separate sync_state.jsonl file.
        On read, the most recent state for each sequence is used.

        Args:
            sequence: The sequence number of the entry to update
            synced: New synced status (if provided)
            sync_attempts: New sync_attempts count (if provided)
            last_sync_error: New error message (if provided)

        Returns:
            True if state was updated successfully
        """
        await self.initialize()

        async with self._lock:
            # Get current state or create new
            current_state = self._sync_states.get(sequence, SyncState())

            # Apply updates
            if synced is not None:
                current_state.synced = synced
            if sync_attempts is not None:
                current_state.sync_attempts = sync_attempts
            if last_sync_error is not None:
                current_state.last_sync_error = last_sync_error
            current_state.updated_at = datetime.now(timezone.utc).isoformat()

            self._sync_states[sequence] = current_state
            state_record = {
                "seq": sequence,
                "synced": current_state.synced,
                "sync_attempts": current_state.sync_attempts,
                "last_sync_error": current_state.last_sync_error,
                "ts": current_state.updated_at,
            }

            try:
                async with aiofiles.open(self._sync_state_file, "a") as f:
                    await f.write(json.dumps(state_record) + "\n")
                    await f.flush()
                logger.debug(f"Sync state updated: seq={sequence}, synced={current_state.synced}")
                return True
            except Exception as e:
                logger.error(f"Failed to persist sync state for seq={sequence}: {e}")
                return False

    async def mark_synced(self, sequence: int) -> None:
        """
        Mark an entry as synced.

        This updates the entry's 'synced' field to True in the WAL file,
        ensuring durability across restarts.
        """
        await self.update_entry(sequence, synced=True)

    async def get_stats(self) -> dict:
        """Get WAL statistics."""
        await self.initialize()

        total_entries = 0
        unsynced_count = 0
        total_size = 0

        wal_files = list(self.data_dir.glob("wal_*.jsonl"))
        for wal_file in wal_files:
            total_size += wal_file.stat().st_size
            try:
                async with aiofiles.open(wal_file, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                total_entries += 1
                                entry = WALEntry.from_json(line)
                                # Check sync state from cache
                                if entry.sequence in self._sync_states:
                                    if not self._sync_states[entry.sequence].synced:
                                        unsynced_count += 1
                                else:
                                    # No sync state means not synced
                                    unsynced_count += 1
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception as e:
                logger.warning(f"Error reading WAL file {wal_file}: {e}")
                continue

        # Add sync state log size
        if self._sync_state_file.exists():
            total_size += self._sync_state_file.stat().st_size

        return {
            "data_dir": str(self.data_dir),
            "current_sequence": self._sequence,
            "total_entries": total_entries,
            "unsynced_entries": unsynced_count,
            "file_count": len(wal_files),
            "total_size_bytes": total_size,
            "current_file": str(self._current_file) if self._current_file else None,
            "sync_states_cached": len(self._sync_states),
        }

    async def compact_sync_state(self) -> dict:
        """
        Compact the sync_state.jsonl file by removing duplicate entries.

        The sync state log is append-only, so over time it accumulates
        multiple entries for the same sequence. This method rewrites the
        file keeping only the most recent state for each sequence.

        Also reloads the in-memory cache from the compacted file to reduce
        memory usage.

        Memory optimization: Instead of loading all WAL sequences into a set,
        we find the min/max sequence range from WAL files (O(1) memory for range).
        States outside this range are pruned as orphans.

        Should be called periodically (e.g., daily) to prevent unbounded
        file and memory growth.

        Returns:
            Compaction statistics including memory_before and memory_after
        """
        await self.initialize()

        if not self._sync_state_file.exists():
            return {"compacted": False, "reason": "no_sync_state_file"}

        async with self._lock:
            memory_before = len(self._sync_states)

            # Count original entries (async)
            original_count = 0
            async with aiofiles.open(self._sync_state_file, "r") as f:
                async for line in f:
                    if line.strip():
                        original_count += 1

            # Read all states (last entry per sequence wins)
            states: Dict[int, dict] = {}
            try:
                async with aiofiles.open(self._sync_state_file, "r") as f:
                    async for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                seq = data.get("seq")
                                if seq is not None:
                                    states[seq] = data
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                return {"compacted": False, "reason": str(e)}

            # Find min/max sequence range in WAL files (memory-efficient)
            # Only need to check first entry of first file and last entry of last file
            min_seq: Optional[int] = None
            max_seq: Optional[int] = None
            wal_files = sorted(self.data_dir.glob("wal_*.jsonl"))

            if wal_files:
                # Get min from first file's first entry
                try:
                    async with aiofiles.open(wal_files[0], "r") as f:
                        async for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line)
                                    min_seq = data.get("seq")
                                    break
                                except (json.JSONDecodeError, KeyError):
                                    continue
                except Exception:
                    pass

                # Get max from last file's last entry
                try:
                    last_seq = None
                    async with aiofiles.open(wal_files[-1], "r") as f:
                        async for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line)
                                    last_seq = data.get("seq")
                                except (json.JSONDecodeError, KeyError):
                                    continue
                    max_seq = last_seq
                except Exception:
                    pass

            # Filter states: keep only sequences within WAL range
            if min_seq is not None and max_seq is not None:
                pruned_states = {
                    seq: data for seq, data in states.items()
                    if min_seq <= seq <= max_seq
                }
            else:
                # Cannot determine WAL range (empty/corrupt files)
                # Safe fallback: keep all states to avoid accidental re-sync
                logger.warning(
                    "compact_sync_state: cannot determine WAL sequence range, "
                    "keeping all sync states to avoid data loss"
                )
                pruned_states = states

            pruned_count = len(states) - len(pruned_states)

            # Write compacted file (only existing sequences)
            temp_file = self._sync_state_file.with_suffix(".tmp")
            try:
                async with aiofiles.open(temp_file, "w") as f:
                    for seq in sorted(pruned_states.keys()):
                        await f.write(json.dumps(pruned_states[seq]) + "\n")

                # Atomic replace (sync, but file handles are closed)
                temp_file.replace(self._sync_state_file)

                # Reload in-memory cache from pruned states
                self._sync_states = {}
                for seq, data in pruned_states.items():
                    self._sync_states[seq] = SyncState(
                        synced=data.get("synced", False),
                        sync_attempts=data.get("sync_attempts", 0),
                        last_sync_error=data.get("last_sync_error"),
                        updated_at=data.get("ts"),
                    )

                return {
                    "compacted": True,
                    "original_entries": original_count,
                    "compacted_entries": len(pruned_states),
                    "removed_duplicates": original_count - len(states),
                    "pruned_orphans": pruned_count,
                    "memory_before": memory_before,
                    "memory_after": len(self._sync_states),
                    "seq_range": [min_seq, max_seq] if min_seq else None,
                }
            except Exception as e:
                if temp_file.exists():
                    temp_file.unlink()
                return {"compacted": False, "reason": str(e)}

    async def sync_to_spine(
        self,
        send_func: Callable[[dict], Any],
        batch_size: int = 100,
        max_retries: int = 3,
    ) -> dict:
        """
        Sync unsynced entries to Spine.

        Single-flight: only one sync can run at a time. If a sync is already
        in progress, returns immediately with zero counts.

        Uses windowed approach: only loads batch_size entries into memory,
        not the entire backlog.

        Args:
            send_func: Async function to send event to Spine
            batch_size: Maximum number of events to process per batch
            max_retries: Maximum retry attempts per event

        Returns:
            Sync statistics (all zeros if another sync is in progress)
        """
        # Single-flight: prevent concurrent syncs
        if self._sync_lock.locked():
            logger.debug("Sync already in progress, skipping")
            return {
                "synced": 0,
                "failed": 0,
                "skipped": 0,
                "processed": 0,
                "skipped_reason": "sync_in_progress",
            }

        async with self._sync_lock:
            synced = 0
            failed = 0
            skipped = 0
            processed = 0

            # Windowed: only load batch_size entries, not entire WAL
            async for entry in self.unsynced_entries(limit=batch_size):
                processed += 1

                # Skip entries that have exceeded max retries
                if entry.sync_attempts >= max_retries:
                    skipped += 1
                    continue

                try:
                    await send_func(entry.event)
                    await self.mark_synced(entry.sequence)
                    synced += 1
                except Exception as e:
                    # Persist sync_attempts and error to disk
                    new_attempts = entry.sync_attempts + 1
                    await self.update_entry(
                        entry.sequence,
                        sync_attempts=new_attempts,
                        last_sync_error=str(e),
                    )
                    failed += 1
                    logger.warning(f"Sync failed for seq={entry.sequence}: {e}")

            return {
                "synced": synced,
                "failed": failed,
                "skipped": skipped,
                "processed": processed,
            }
