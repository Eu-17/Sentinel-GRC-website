"""Container entry point. All accepted settings are supplied by the host."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")),
                workers=1, access_log=False, server_header=False, limit_concurrency=50,
                timeout_keep_alive=5)
