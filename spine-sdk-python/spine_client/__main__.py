# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Allow running spine_client as a module:
    python -m spine_client demo
    python -m spine_client log '{"event_type": "test"}'
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
