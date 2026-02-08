import fastapi
from fastapi import UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from operations import analyze_logs
from prompt import ANALYSIS_PROFILES
import uvicorn
import os

app = fastapi.FastAPI()

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    """Serve the main HTML page for the upload and analysis interface."""
    return FileResponse(os.path.join(static_dir, "index.html"), media_type="text/html")

@app.post ("/analyse")
async def analyse_log_file(
    file: UploadFile = File(...),
    profile: str = Form("general"),
):
    """
    Analyze an uploaded log file and return structured + markdown results.

    Args:
        file (UploadFile): Uploaded `.log` or `.txt` file.
        profile (str): Analysis profile key.

    Returns:
        dict: Analysis payload with markdown report and structured findings.
        JSONResponse: Error payload when validation or processing fails.
    """
    if not file.filename.endswith(".txt") and not file.filename.endswith(".log"):
        return JSONResponse(
            content={"error": "Please upload a valid log file with a .log or .txt extension."},
            status_code=400
        )
    if profile not in ANALYSIS_PROFILES:
        return JSONResponse(
            content={
                "error": "Invalid profile.",
                "available_profiles": list(ANALYSIS_PROFILES.keys()),
            },
            status_code=400,
        )

    try:
        log_data = await file.read()            # read the file content as bytes
        log_data = log_data.decode("utf-8", errors="ignore")  # decode bytes to string, ignoring errors
        if not log_data.strip():
            return JSONResponse(
                content={"error": "The uploaded log file is empty."},
                status_code=400
            )
        analysis_result = analyze_logs(log_data, profile=profile)
        return {
            "profile": profile,
            "analysis": analysis_result["markdown_report"],
            "structured": {
                "overall_summary": analysis_result.get("overall_summary", ""),
                "global_patterns": analysis_result.get("global_patterns", []),
                "findings": analysis_result.get("findings", []),
                "chunk_count": analysis_result.get("chunk_count", 0),
            },
            "available_profiles": ANALYSIS_PROFILES,
        }
    except Exception as e:
        return JSONResponse(
            content={"error": f"An error occurred while processing the file: {str(e)}"},
            status_code=500
        )



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
