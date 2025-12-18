from fastapi import FastAPI, Request
import logging

logging.basicConfig(level=logging.INFO)

app = FastAPI()

@app.post("/test")
async def receive_data(request: Request):
    data = await request.json()
    logging.info(f"Received data: {data}")
    return {"status": "ok", "data_received": data}
