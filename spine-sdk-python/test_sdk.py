import asyncio

from spine_client import AuditEvent, SpineClient


async def main():
    async with SpineClient('http://localhost:3000', local_wal_dir='./test_wal') as client:
        response = await client.log(AuditEvent(
            event_type='test.event',
            payload={'message': 'hello'}
        ))
        print(f'Logged: seq={response.sequence}, hash={response.payload_hash}')

        # Show stats
        stats = await client.get_stats()
        print(f'WAL stats: {stats.get("local_wal")}')

asyncio.run(main())
