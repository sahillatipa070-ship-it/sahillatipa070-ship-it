# VASUDHA

Watershed intelligence portal with an interactive map, account flows, organization photo uploads, intervention records, analytics, and data exports.

## Run locally

Requires Python 3.10 or newer. There are no third-party Python dependencies.

```powershell
python server.py
```

Then open <http://127.0.0.1:8000>. Set `PORT` to use a different port. On first start, the server creates `data/waterscope.sqlite3` and `data/uploads/` beside the server.

## Data and map services

Application records and uploaded images are stored on the machine running the server. The map uses Esri World Imagery and OpenStreetMap data; place search uses OpenStreetMap Nominatim. Follow the providers' attribution and service terms before public or commercial use.

The app does not fabricate watershed boundaries, soil moisture, NDVI, land degradation, or change-detection measurements. Those analyses require a verified imagery or sensor source and watershed boundary.
