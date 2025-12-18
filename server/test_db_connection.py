import asyncpg
import asyncio

async def test():
    conn = await asyncpg.connect(
        user="fim_user",
        password="StrongPasswordHere",
        database="fim_db",
        host="127.0.0.1",
        port=5432,
    )
    print("Connected!")
    await conn.close()

asyncio.run(test())

